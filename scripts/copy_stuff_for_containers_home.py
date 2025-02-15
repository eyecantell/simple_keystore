import platform
import os
import shutil
import stat
from pathlib import Path


# When run on a machine, this copies items into hostPathPrefixForMounts/stuff_for_containers_home from the users home directory
# When run within a container, it copies items from the mounted stuff_for_containers_home directory (/mounted/stuff_for_containers_home)
# to the user's home dir in the container
# This needs to be run any time info in the user's home directory needs to be updated in the container
stuff_for_container_home_dir_name = "stuff_for_containers_home"

# These are the (default) paths that will be copied when not in docker
wanted_paths = [".netrc", ".gitconfig", ".bashrc"]

dirs = {
    "PRW-Dev1": {
        # Running on the development machine, will copy from (user) home_dir to the stuff_for_containers_full_path that will be mounted
        "from_path": "/home/eyecantell",
        "to_path": os.path.join("/mnt/c/Users/eyeca", stuff_for_container_home_dir_name),
        "wanted_paths": wanted_paths,
    },
    "docker_container": {
        # Running in a docker container, will copy from stuff_for_containers_full_path (that should be mounted) to (user) home_dir
        "from_path": os.path.join("/mounted", stuff_for_container_home_dir_name),
        "to_path": "/home/developer/",
    },
}


def is_running_in_docker():
    """Check if the script is running inside a Docker container."""
    if os.path.exists("/.dockerenv"):
        print("is_running_in_docker returning true")
        return True
    print("is_running_in_docker returning false")
    return False


def copy_path(source_path, destination_path):
    """Copy from source to destination."""
    if not os.path.exists(source_path):
        raise RuntimeError(f"copy_path: Could not locate source_path '{source_path}'")

    if os.path.isdir(source_path):
        dest_path_with_dirname = os.path.join(destination_path, os.path.basename(source_path))
        print(f"Copying directory {source_path} to {dest_path_with_dirname}")
        shutil.copytree(source_path, dest_path_with_dirname, dirs_exist_ok=True)

    elif os.path.isfile(source_path):
        print(f"Copying file {source_path} to {destination_path}")
        shutil.copy2(source_path, destination_path)


def main():
    system_info = platform.uname()
    print(f"System info is {system_info}")

    if system_info.node in dirs:
        # Specific settings for this machine were defined
        from_path = dirs[system_info.node]["from_path"]
        to_path = dirs[system_info.node]["to_path"]

        print(f"Running on {system_info.node} - will copy wanted files/dir from {from_path} to {to_path}")

        # Copy wanted files
        for path in wanted_paths:
            full_path_to_copy = os.path.join(from_path, path)
            copy_path(full_path_to_copy, to_path)

        print(f"After copy, ls {to_path} gives:", os.listdir(to_path))

    elif is_running_in_docker():
        from_path = dirs["docker_container"]["from_path"]
        to_path = dirs["docker_container"]["to_path"]

        print(
            f"Running inside Docker container - will copy contents of {from_path} to {to_path} and change permissions"
        )

        for path in os.listdir(from_path):
            copy_path(os.path.join(from_path, path), to_path)

        # Change the ~/.netrc and ~/.kube/config file permissions to 600
        os.chmod(os.path.join(Path.home(), ".netrc"), stat.S_IREAD | stat.S_IWRITE)
        os.chmod(os.path.join(Path.home(), ".kube/config"), stat.S_IREAD | stat.S_IWRITE)

    else:
        raise RuntimeError(f"Dunno what to do for machine {system_info} when not running in docker")


if __name__ == "__main__":
    main()
