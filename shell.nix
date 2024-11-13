{ pkgs ? import <nixpkgs> {} }:

let
  python = pkgs.python311;
  pythonEnv = python.withPackages (ps: with ps; [
    joblib
    numba
    numpy
    pandas
    scapy
    scikit-learn
    psutil
    django
  ]);

in
pkgs.mkShell {
  name = "python-env";

  buildInputs = [
    pythonEnv
    pkgs.stdenv.cc.cc.lib
  ];

  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.stdenv.cc.cc.lib}/lib:$LD_LIBRARY_PATH
    export PYTHONPATH=${pythonEnv}/lib/python3.11/site-packages:$PYTHONPATH
  '';
}
