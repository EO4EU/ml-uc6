"""A generated module for Uc6 functions

This module has been generated via dagger init and serves as a reference to
basic module structure as you get started with Dagger.

Two functions have been pre-created. You can modify, delete, or add to them,
as needed. They demonstrate usage of arguments and return types using simple
echo and grep commands. The functions can be called from the dagger CLI or
from one of the SDKs.

The first line in this comment block is a short description line and the
rest is a long description with more detail on the module's purpose or usage,
if appropriate. All modules should have a short description.
"""

# NOTE: it's recommended to move your code into other files in this package
# and keep __init__.py for imports only, according to Python's convention.
# The only requirement is that Dagger needs to be able to import a package
# called "main" (i.e., src/main/).
#
# For example, to import from src/main/main.py:
# >>> from .main import Uc6 as Uc6

import dagger
from typing import Annotated
from dagger import Doc, dag, function, object_type

@object_type
class Uc6:
    @function
    async def build(
        self,
        tag: Annotated[str, Doc("Image tag")],
        wkd: Annotated[
            dagger.Directory,
            Doc("Location of directory containing Dagger files"),
        ],
    ) -> dagger.Directory:
        """Build and publish image from existing Dockerfile"""
        return await (
            dag.container()
            .from_("gcr.io/kaniko-project/executor:debug")
            .with_mounted_directory("/workspace", wkd)
            .with_exec(
                [
                    "/kaniko/executor",
                    "--context", 
                    "dir:///workspace/",
                    "--dockerfile",
                    "/workspace/Dockerfile",
                    "--no-push",
                    "--oci-layout-path",
                    f"/workspace/{tag}"
                ]
            )
            .directory(f"/workspace/{tag}")
        )
    
    @function
    async def scan(
        self,
        severity: Annotated[str, Doc("Severity level")],
        exit: Annotated[str, Doc("Exit code")],
        tag: Annotated[str, Doc("Image tag")],
        wkd: Annotated[
            dagger.Directory,
            Doc("Location of directory containing Dagger files"),
        ],
    ) -> dagger.File:
        """Scan image to detect vulnerabilities"""
        template = (
            dag.container()
            .from_("alpine:latest")
            .with_directory("/src", wkd)
            .with_workdir("/src")
            .with_exec(
                [
                    "wget",
                    "https://raw.githubusercontent.com/aquasecurity/trivy/refs/heads/main/contrib/html.tpl"
                ]
            )
        )
        return await (
            dag.trivy().base()
            .with_directory("/src", wkd)
            .with_file("/src/html.tpl", template.file("/src/html.tpl"))
            .with_exec(
                [
                    "trivy",
                    "image",
                    "--db-repository",
                    "public.ecr.aws/aquasecurity/trivy-db",
                    "--java-db-repository",
                    "public.ecr.aws/aquasecurity/trivy-java-db",
                    "--exit-code",
                    exit,
                    "--severity",
                    severity,
                    "--format",
                    "template",
                    "--template",
                    "@/src/html.tpl",
                    "--output",
                    f"/src/vulnerabilities.html",
                    "--input",
                    f"/src/{tag}"
                ]
            )
            .file(f"/src/vulnerabilities.html")
        )

    @function
    async def sbom(
        self,
        tag: Annotated[str, Doc("Image tag")],
        wkd: Annotated[
            dagger.Directory,
            Doc("Location of directory containing Dagger files"),
        ],
    ) -> dagger.File:
        """Scan image and produce SBOM file"""
        return await (
            dag.trivy().base()
            .with_directory("/src", wkd)
            .with_exec(
                [
                    "trivy",
                    "image",
                    "--db-repository",
                    "public.ecr.aws/aquasecurity/trivy-db",
                    "--java-db-repository",
                    "public.ecr.aws/aquasecurity/trivy-java-db",
                    "--exit-code",
                    "0",
                    "--format",
                    "cyclonedx",
                    "--output",
                    f"/src/sbom-report.cdx.json",
                    "--input",
                    f"/src/{tag}"
                ]
            )
            .file(f"/src/sbom-report.cdx.json")
        )

    @function
    async def push(
        self,
        registry: Annotated[str, Doc("Registry address")],
        repo: Annotated[str, Doc("Registry repo")],
        app: Annotated[str, Doc("Application name")],
        tag: Annotated[str, Doc("Image tag")],
        username: Annotated[str, Doc("Registry username")],
        password: Annotated[dagger.Secret, Doc("Registry password")],
        wkd: Annotated[
            dagger.Directory,
            Doc("Location of directory containing Dagger files"),
        ],
    ) -> str:
        """Build and publish image from existing Dockerfile"""
        return await (
            dag.container(platform=dagger.Platform("linux/amd64"))
            .with_directory("/src", wkd)
            .with_workdir("/src")
            .directory("/src")
            .docker_build()
            .with_registry_auth(registry, username, password)
            .publish(f"{registry}/{username}/{repo}/{app}:{tag}")
        )
    
    @function
    async def update(
        self,
        gitlab: Annotated[str, Doc("Gitlab address")],
        service: Annotated[str, Doc("Service branch")],
        repo: Annotated[str, Doc("Repository name")],
        username: Annotated[str, Doc("Repository username")],
        password: Annotated[dagger.Secret, Doc("Repository password")],
        wkd: Annotated[
            dagger.Directory,
            Doc("Location of directory containing Dagger files"),
        ],
    ) -> dagger.Directory:
        """Create helm chart from cookiecutter template"""
        token = await password.plaintext()
        return await (
            dag.container()
            .from_("harness/cookiecutter:latest")
            .with_directory("/src", wkd)
            .with_workdir("/src")
            .with_exec(
                [
                    "cookiecutter",
                    "--no-input",
                    "--config-file",
                    "cookiecutter-config.yaml",
                    "--checkout",
                    f"{service}",
                    f"https://{username}:{token}@{gitlab}/{username}/cookiecutter-helm-template.git"
                ]
            )
            .directory(f"/src/{repo}")
        )
