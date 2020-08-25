with import <nixpkgs> {};
let
  my-python-packages = python-packages: [
    python-packages.pip
    # python-packages.numpy
    python-packages.setuptools
    python-packages.pandas
    python-packages.ipython
    python-packages.psycopg2
    python-packages.cffi
  ];
  my-python = python37.withPackages my-python-packages;
in
  pkgs.mkShell {
    buildInputs = [
      bashInteractive
      my-python
      libgcc
    ];
    shellHook = ''
      export PIP_PREFIX="$(pwd)/_build/pip_packages"
      export PYTHONPATH="$(pwd)/_build/pip_packages/lib/python3.7/site-packages:$PYTHONPATH" 
      unset SOURCE_DATE_EPOCH
    '';
  }
