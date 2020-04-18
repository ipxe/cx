#!/usr/bin/env python3

"""Setup script"""

from pathlib import Path
from setuptools import Extension, setup, find_packages
from Cython.Build import cythonize

cdir = Path('../c').resolve()
incdir = cdir / 'include'
libdir = cdir / 'src' / '.libs'

extensions = [Extension(
    '*', ['libcx/*.pyx'],
    libraries=['cx'],
    include_dirs=[str(incdir)],
    library_dirs=[str(libdir)],
    runtime_library_dirs=[str(libdir)],
)]

setup(
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(exclude=['test']),
    use_scm_version={'root': '..'},
    python_requires='>=3.7',
    setup_requires=[
        'Cython',
        'setuptools_scm',
    ],
    ext_modules=cythonize(extensions, language_level=3, annotate=True),
    test_suite='test',
    zip_safe=False,
)
