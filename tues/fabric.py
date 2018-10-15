# coding: utf-8

from __future__ import absolute_import, print_function

import re

from six.moves.queue import Queue, Empty

from invoke.util import ExceptionHandlingThread
from invoke.watchers import FailingResponder
from invoke.exceptions import Failure

from fabric2 import Connection as _Connection
from fabric2.group import Group as _Group, GroupResult
from fabric2.exceptions import GroupException


class RetryingResponder(FailingResponder):
    """
    Variant of `Responder` which is capable of detecting incorrect responses.

    This class adds a ``sentinel`` parameter to ``__init__``, and its
    ``submit`` will raise `.ResponseNotAccepted` if it detects that sentinel
    value in the stream.

    .. versionadded:: 1.0
    """

    def __init__(self, pattern, response, sentinel):
        super(RetryingResponder, self).__init__(pattern, response, sentinel)
        self.failed = False

    def submit(self, stream):
        failed = self.pattern_matches(stream, self.sentinel, "failure_index")
        if failed:
            self.failed = True
        return (self.response(self.failed) for _ in self.pattern_matches(stream, self.pattern, "index"))


class Connection(_Connection):

    def _sudo(self, runner, command, **kwargs):
        prompt = self.config.sudo.prompt
        password = kwargs.pop("password", self.config.sudo.password)
        user = kwargs.pop("user", self.config.sudo.user)
        # TODO: allow subclassing for 'get the password' so users who REALLY
        # want lazy runtime prompting can have it easily implemented.
        # TODO: want to print a "cleaner" echo with just 'sudo <command>'; but
        # hard to do as-is, obtaining config data from outside a Runner one
        # holds is currently messy (could fix that), if instead we manually
        # inspect the config ourselves that duplicates logic. NOTE: once we
        # figure that out, there is an existing, would-fail-if-not-skipped test
        # for this behavior in test/context.py.
        # TODO: once that is done, though: how to handle "full debug" output
        # exactly (display of actual, real full sudo command w/ -S and -p), in
        # terms of API/config? Impl is easy, just go back to passing echo
        # through to 'run'...
        user_flags = ""
        if user is not None:
            user_flags = "-H -u {} ".format(user)
        command = self._prefix_commands(command)
        cmd_str = "sudo -S -p '{}' {}{}".format(prompt, user_flags, command)
        watcher = RetryingResponder(
            pattern=re.escape(prompt),
            response=lambda *a, **k: "{}\n".format(password(*a, **k)),
            sentinel="Sorry, try again.[\r\n]+",
        )
        # Ensure we merge any user-specified watchers with our own.
        # NOTE: If there are config-driven watchers, we pull those up to the
        # kwarg level; that lets us merge cleanly without needing complex
        # config-driven "override vs merge" semantics.
        # TODO: if/when those semantics are implemented, use them instead.
        # NOTE: config value for watchers defaults to an empty list; and we
        # want to clone it to avoid actually mutating the config.
        watchers = kwargs.pop("watchers", list(self.config.run.watchers))
        watchers.append(watcher)
        try:
            return runner.run(cmd_str, watchers=watchers, **kwargs)
        except Failure as failure:
            # Transmute failures driven by our FailingResponder, into auth
            # failures - the command never even ran.
            # TODO: wants to be a hook here for users that desire "override a
            # bad config value for sudo.password" manual input
            # NOTE: as noted in #294 comments, we MAY in future want to update
            # this so run() is given ability to raise AuthFailure on its own.
            # For now that has been judged unnecessary complexity.
            if isinstance(failure.reason, ResponseNotAccepted):
                # NOTE: not bothering with 'reason' here, it's pointless.
                # NOTE: using raise_from(..., None) to suppress Python 3's
                # "helpful" multi-exception output. It's confusing here.
                error = AuthFailure(result=failure.result, prompt=prompt)
                raise_from(error, None)
            # Reraise for any other error so it bubbles up normally.
            else:
                raise


class Group(_Group):

    def __init__(self, *hosts, **kwargs):
        self.extend([Connection(host, **kwargs) for host in hosts])


class SerialGroup(Group):

    def run(self, *args, **kwargs):
        def run(cxn, *args, **kwargs):
            return cxn.run(*args, **kwargs)
        return self.call(run, *args, **kwargs)

    def call(self, func, *args, **kwargs):
        results = GroupResult()
        excepted = False
        for cxn in self:
            try:
                results[cxn] = func(cxn, *args, **kwargs)
            except Exception as e:
                results[cxn] = e
                excepted = True
        if excepted:
            raise GroupException(results)
        return results


def thread_worker(current_cxn, input_queue, output_queue, func, args, kwargs):
    while True:
        try:
            cxn = input_queue.get_nowait()
            current_cxn[:] = [cxn]
        except Empty:
            return
        result = func(cxn, *args, **kwargs)
        output_queue.put((cxn, result))


class ThreadingGroup(Group):

    def __init__(self, *args, **kwargs):
        self._parallel = kwargs.pop("parallel", 10)
        super(ThreadingGroup, self).__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        def func(cxn, *args, **kwargs):
            return cxn.run(*args, **kwargs)
        return self.call(func, *args, **kwargs)

    def call(self, func, *args, **kwargs):
        results = GroupResult()
        output_queue = Queue()
        input_queue = Queue()
        threads = []

        # TODO: Filling the queue before starting threads allows the worker to just
        # check if the queue if it is empty and exit, but we will also have all connections
        # on the queue at once, which may be bad with a *very* large number of hosts..
        for cxn in self:
            input_queue.put(cxn)

        for _ in range(self._parallel):
            my_kwargs = dict(
                current_cxn=[None],
                input_queue=input_queue,
                output_queue=output_queue,
                func=func,
                args=args,
                kwargs=kwargs,
            )
            thread = ExceptionHandlingThread(
                target=thread_worker, kwargs=my_kwargs
            )
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            # TODO: configurable join timeout
            # TODO: (in sudo's version) configurability around interactive
            # prompting resulting in an exception instead, as in v1
            thread.join()
        # Get non-exception results from queue
        while not output_queue.empty():
            # TODO: io-sleep? shouldn't matter if all threads are now joined
            cxn, result = output_queue.get(block=False)
            # TODO: outstanding musings about how exactly aggregate results
            # ought to ideally operate...heterogenous obj like this, multiple
            # objs, ??
            results[cxn] = result
        # Get exceptions from the threads themselves.
        # TODO: in a non-thread setup, this would differ, e.g.:
        # - a queue if using multiprocessing
        # - some other state-passing mechanism if using e.g. coroutines
        # - ???
        excepted = False
        for thread in threads:
            wrapper = thread.exception()
            if wrapper is not None:
                # Outer kwargs is Thread instantiation kwargs, inner is kwargs
                # passed to thread target/body.
                cxn = wrapper.kwargs["kwargs"]["current_cxn"][0]
                # This is probably an "internal" exception, since no cxn is set,
                # we just reraise the exception because it's hell to debug this otherwise
                if cxn is None:
                    raise wrapper.type, wrapper.value, wrapper.traceback
                results[cxn] = wrapper.value
                excepted = True
        if excepted:
            raise GroupException(results)
        return results
