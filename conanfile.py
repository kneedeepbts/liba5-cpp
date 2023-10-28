# This file is managed by Conan, contents will be overwritten.
# To keep your changes, remove these comment lines, but the plugin won't be able to modify your requirements

from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout, CMakeToolchain

class ConanApplication(ConanFile):
    name = "liba5"
    version = "0.1.0"

    license = "BSD" # Probably should update this to the more formal name
    author = "Daniel Williams <dwilliams@port8080.net>"
    url = "https://github.com/kneedeepbts/liba5-cpp"
    description = "Library containing the cryptographic algorithms for kneedeepbts."

    package_type = "library"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False]
    }
    default_options = {
        "shared": False,
        "fPIC": True
    }

    generators = "CMakeDeps"
    exports_sources = "CMakeLists.txt", "src/*", "tests/*"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.user_presets_path = False
        tc.generate()

    def requirements(self):
        requirements = self.conan_data.get('requirements', [])
        for requirement in requirements:
            self.requires(requirement)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["liba5"]