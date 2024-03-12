import pathlib as _pathlib
import time as _time

import pytest as _pytest
import pytest_container as _pytest_container
import pytest_container.container as _container

import tues as _tues


@_pytest.fixture(scope="module")
def username():
    return "pytest"


@_pytest.fixture(scope="module")
def password():
    return "pytest-password"


@_pytest.fixture(scope="function")
def pm(password):
    return _tues.PasswordManager(password=password)


def get_pubkey():
    with open("test/id_ecdsa.pub", "r") as fobj:
        return fobj.read().strip()


@_pytest.fixture(scope="module", autouse="true")
def ssh_config(tmp_path_factory, username):
    home = tmp_path_factory.mktemp("home", numbered=False)
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir()
    ssh_dir.joinpath("config").write_text(
        f"User {username}\n"
        "IdentityFile ~/.ssh/id_ecdsa\n"
    )

    ssh_dir.joinpath("id_ecdsa").write_bytes(_pathlib.Path("test/id_ecdsa").read_bytes())

    mp = _pytest.MonkeyPatch()
    # FIXME: This isn't pretty
    # Explicitly set to the default path before changing $HOME.
    mp.setenv(
        "CONTAINERS_STORAGE_CONF",
        str(_pathlib.Path.home() / ".config/containers/storage.conf"),
    )
    # So the ssh client picks up our config.
    mp.setenv("HOME", str(home))
    yield
    mp.undo()


@_pytest.fixture(scope="module")
def host(pytestconfig, container_runtime, username, password):
    container = _pytest_container.Container(
        url=(
            # FIXME: Does pinning actually speed things up?
            "docker.io/linuxserver/openssh-server"
            ":version-9.6_p1-r0"
            "@sha256:19332c6d543f05f181573604b19f7c23529d8b86b5e622cf2d79c7a97a7afe0a"
        ),
        extra_environment_variables={
            "PASSWORD_ACCESS": "true",
            "USER_NAME": username,
            "USER_PASSWORD": password,
            "SUDO_ACCESS": "true",
            "PUBLIC_KEY": get_pubkey(),
        },
        forwarded_ports=[_pytest_container.PortForwarding(container_port=2222)],
    )

    with _container.ContainerLauncher(
        container=container,
        container_runtime=container_runtime,
        rootdir=pytestconfig.rootpath,
    ) as launcher:
        launcher.launch_container()
        _time.sleep(0.5)  # The ssh server inside the container is not immediately available
        container_data = launcher.container_data
        container_data.connection.run("echo Defaults lecture=never >/etc/sudoers.d/pytest")
        port = container_data.forwarded_ports[0].host_port
        #yield f"localhost:{port}"
        yield ("localhost", port)

    # Created and left behind by the container launcher.
    _pathlib.Path("port_check.lock").unlink(missing_ok=True)
