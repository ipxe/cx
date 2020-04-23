#!/usr/bin/env python3

"""Setup script"""

from pathlib import Path
import subprocess
from setuptools import Extension, setup, find_packages, findall
from setuptools.command.build_ext import build_ext
from setuptools.command.egg_info import egg_info


# Use cythonize, if Cython is installed
try:
    from Cython.Build import cythonize
except ImportError:
    if Path('libcx/cdefs.c').exists():
        cythonize = lambda exts, **kwargs: exts
    else:
        raise


# Use local libcx C library, if present
cxgitdir = Path('../c')
cxdistdir = Path('dist-libcx')
cxdir = next((x for x in (cxgitdir, cxdistdir)
              if (x / 'src/generator.c').exists()), None)


def libcx_prep():
    """Prepare libcx C library build directory"""
    if not (cxdir / 'configure').exists():
        subprocess.check_call(['./autogen.sh'], cwd=cxdir)
    if not (cxdir / 'Makefile').exists():
        subprocess.check_call(['./configure'], cwd=cxdir)


class EggInfoCommand(egg_info):
    """Custom egg_info command"""

    def libcx_dist(self):
        """Build libcx C library distribution"""
        libcx_prep()
        subprocess.check_call(['make', 'distdir=dist-libcx', 'distdir'],
                              cwd=cxdir)
        if cxdistdir.exists():
            cxdistdir.unlink()
        cxdistdir.symlink_to(cxdir / 'dist-libcx')
        cxdistfile = sorted(findall(cxdistdir))
        with open('MANIFEST.in', 'wt') as f:
            f.write('# Generated automatically by setup.py - do not edit\n')
            f.writelines('include %s\n' % x for x in cxdistfile)

    def find_sources(self):
        """Find sources"""
        if cxdir == cxgitdir:
            self.libcx_dist()
        super().find_sources()


class BuildExtCommand(build_ext):
    """Custom build_ext command"""

    user_options = build_ext.user_options + [
        ('extlibcx', None, "Force use of externally installed libcx"),
    ]
    boolean_options = build_ext.boolean_options + [
        'extlibcx',
    ]

    def initialize_options(self):
        """Initialize options"""
        super().initialize_options()
        self.extlibcx = cxdir is None

    @staticmethod
    def pkgconf(libname, *args):
        """Run pkg-config and capture output"""
        cmd = ['pkg-config', libname, *args]
        return subprocess.check_output(cmd).decode().split()

    @classmethod
    def pkgconf_vals(cls, libname, *args):
        """Run pkg-config, capture output, and strip initial -<X>"""
        return [x[2:] for x in cls.pkgconf(libname, *args)]

    def pkgconf_ext(self, libname):
        """Run pkg-config to get extension attributes"""
        return {
            'include_dirs': self.pkgconf_vals(libname, '--cflags-only-I'),
            'library_dirs': self.pkgconf_vals(libname, '--libs-only-L'),
            'libraries': self.pkgconf_vals(libname, '--libs-only-l'),
            'extra_compile_args': self.pkgconf(libname, '--cflags-only-other'),
            'extra_link_args': self.pkgconf(libname, '--libs-only-other'),
        }

    def libcx_build(self):
        """Build libcx C library and return extension attributes"""
        libcx_prep()
        subprocess.check_call(['make'], cwd=cxdir)
        incdir = str(cxdir / 'include')
        libdir = str(cxdir / 'src/.libs')
        return {
            'include_dirs': [incdir],
            'extra_objects': [
                '-L' + libdir, '-Wl,-Bstatic', '-lcx', '-Wl,-Bdynamic'
            ],
        }

    @staticmethod
    def merge_attributes(ext, params):
        """Merge extension parameters"""
        for name, values in params.items():
            attr = getattr(ext, name)
            attr.extend(x for x in values if x not in attr)

    def run(self):
        """Run command"""
        cx = self.pkgconf_ext('cx') if self.extlibcx else self.libcx_build()
        openssl = self.pkgconf_ext('openssl')
        for ext in self.extensions:
            self.merge_attributes(ext, cx)
            self.merge_attributes(ext, openssl)
        super().run()


setup(
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(exclude=['test']),
    use_scm_version={
        'root': '..',
        'tag_regex': r'^python-(?P<version>\d+(?:\.\d+)*)$',
        'git_describe_command': ('git describe --dirty --tags --long '
                                 '--match python-*'),
    },
    python_requires='>=3.4',
    cmdclass={
        'egg_info': EggInfoCommand,
        'build_ext': BuildExtCommand,
    },
    setup_requires=[
        'setuptools_scm',
    ],
    install_requires = [
        'pyOpenSSL',
    ],
    ext_modules=cythonize(
        [
            Extension('libcx.cdefs', ['libcx/cdefs.pyx']),
            Extension('libcx.generator', ['libcx/generator.pyx']),
            Extension('libcx.seedcalc', ['libcx/seedcalc.pyx']),
            Extension('libcx.preseed', ['libcx/preseed.pyx']),
        ],
        language_level=3,
        annotate=True,
    ),
    test_suite='test',
    zip_safe=False,
)
