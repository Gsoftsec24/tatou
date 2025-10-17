"""watermarking_cli.py

Command-line interface for the PDF watermarking toolkit.

Usage examples
--------------

List available methods:
    python -m watermarking_cli methods

Explore a PDF and write a JSON node tree:
    python -m watermarking_cli explore input.pdf --out tree.json

Embed a secret using the default method (toy-eof) and write a new PDF:
    python -m watermarking_cli embed input.pdf output.pdf --key-prompt --secret "hello"

Extract a secret:
    python -m watermarking_cli extract input.watermarked.pdf --key-prompt

Exit codes
----------
0   success
2   invalid usage / bad input
3   secret not found
4   invalid key / authentication failed
5   other watermarking error
"""
from __future__ import annotations

from typing import Iterable, Optional
import argparse
import json
import os
import sys
import getpass
import email
import smtplib
from email.message import EmailMessage

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError
)
from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, store_recipient_credentials

__version__ = "0.1.0"
from inspect import signature as _mutmut_signature
from typing import Annotated
from typing import Callable
from typing import ClassVar


MutantDict = Annotated[dict[str, Callable], "Mutant"]


def _mutmut_trampoline(orig, mutants, call_args, call_kwargs, self_arg = None):
    """Forward call to original or mutated function, depending on the environment"""
    import os
    mutant_under_test = os.environ['MUTANT_UNDER_TEST']
    if mutant_under_test == 'fail':
        from mutmut.__main__ import MutmutProgrammaticFailException
        raise MutmutProgrammaticFailException('Failed programmatically')      
    elif mutant_under_test == 'stats':
        from mutmut.__main__ import record_trampoline_hit
        record_trampoline_hit(orig.__module__ + '.' + orig.__name__)
        result = orig(*call_args, **call_kwargs)
        return result
    prefix = orig.__module__ + '.' + orig.__name__ + '__mutmut_'
    if not mutant_under_test.startswith(prefix):
        result = orig(*call_args, **call_kwargs)
        return result
    mutant_name = mutant_under_test.rpartition('.')[-1]
    if self_arg:
        # call to a class method where self is not bound
        result = mutants[mutant_name](self_arg, *call_args, **call_kwargs)
    else:
        result = mutants[mutant_name](*call_args, **call_kwargs)
    return result

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_orig(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_1(path: str) -> str:
    with open(None, "r", encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_2(path: str) -> str:
    with open(path, None, encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_3(path: str) -> str:
    with open(path, "r", encoding=None) as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_4(path: str) -> str:
    with open("r", encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_5(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_6(path: str) -> str:
    with open(path, "r", ) as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_7(path: str) -> str:
    with open(path, "XXrXX", encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_8(path: str) -> str:
    with open(path, "R", encoding="utf-8") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_9(path: str) -> str:
    with open(path, "r", encoding="XXutf-8XX") as fh:
        return fh.read()

# --------------------
# Helpers
# --------------------

def x__read_text_from_file__mutmut_10(path: str) -> str:
    with open(path, "r", encoding="UTF-8") as fh:
        return fh.read()

x__read_text_from_file__mutmut_mutants : ClassVar[MutantDict] = {
'x__read_text_from_file__mutmut_1': x__read_text_from_file__mutmut_1, 
    'x__read_text_from_file__mutmut_2': x__read_text_from_file__mutmut_2, 
    'x__read_text_from_file__mutmut_3': x__read_text_from_file__mutmut_3, 
    'x__read_text_from_file__mutmut_4': x__read_text_from_file__mutmut_4, 
    'x__read_text_from_file__mutmut_5': x__read_text_from_file__mutmut_5, 
    'x__read_text_from_file__mutmut_6': x__read_text_from_file__mutmut_6, 
    'x__read_text_from_file__mutmut_7': x__read_text_from_file__mutmut_7, 
    'x__read_text_from_file__mutmut_8': x__read_text_from_file__mutmut_8, 
    'x__read_text_from_file__mutmut_9': x__read_text_from_file__mutmut_9, 
    'x__read_text_from_file__mutmut_10': x__read_text_from_file__mutmut_10
}

def _read_text_from_file(*args, **kwargs):
    result = _mutmut_trampoline(x__read_text_from_file__mutmut_orig, x__read_text_from_file__mutmut_mutants, args, kwargs)
    return result 

_read_text_from_file.__signature__ = _mutmut_signature(x__read_text_from_file__mutmut_orig)
x__read_text_from_file__mutmut_orig.__name__ = 'x__read_text_from_file'


def x__read_text_from_stdin__mutmut_orig() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("No data received on stdin")
    return data


def x__read_text_from_stdin__mutmut_1() -> str:
    data = None
    if not data:
        raise ValueError("No data received on stdin")
    return data


def x__read_text_from_stdin__mutmut_2() -> str:
    data = sys.stdin.read()
    if data:
        raise ValueError("No data received on stdin")
    return data


def x__read_text_from_stdin__mutmut_3() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError(None)
    return data


def x__read_text_from_stdin__mutmut_4() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("XXNo data received on stdinXX")
    return data


def x__read_text_from_stdin__mutmut_5() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("no data received on stdin")
    return data


def x__read_text_from_stdin__mutmut_6() -> str:
    data = sys.stdin.read()
    if not data:
        raise ValueError("NO DATA RECEIVED ON STDIN")
    return data

x__read_text_from_stdin__mutmut_mutants : ClassVar[MutantDict] = {
'x__read_text_from_stdin__mutmut_1': x__read_text_from_stdin__mutmut_1, 
    'x__read_text_from_stdin__mutmut_2': x__read_text_from_stdin__mutmut_2, 
    'x__read_text_from_stdin__mutmut_3': x__read_text_from_stdin__mutmut_3, 
    'x__read_text_from_stdin__mutmut_4': x__read_text_from_stdin__mutmut_4, 
    'x__read_text_from_stdin__mutmut_5': x__read_text_from_stdin__mutmut_5, 
    'x__read_text_from_stdin__mutmut_6': x__read_text_from_stdin__mutmut_6
}

def _read_text_from_stdin(*args, **kwargs):
    result = _mutmut_trampoline(x__read_text_from_stdin__mutmut_orig, x__read_text_from_stdin__mutmut_mutants, args, kwargs)
    return result 

_read_text_from_stdin.__signature__ = _mutmut_signature(x__read_text_from_stdin__mutmut_orig)
x__read_text_from_stdin__mutmut_orig.__name__ = 'x__read_text_from_stdin'


def x__resolve_secret__mutmut_orig(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("Secret: ")


def x__resolve_secret__mutmut_1(args: argparse.Namespace) -> str:
    if args.secret is None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("Secret: ")


def x__resolve_secret__mutmut_2(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("Secret: ")


def x__resolve_secret__mutmut_3(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(None)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("Secret: ")


def x__resolve_secret__mutmut_4(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass(None)


def x__resolve_secret__mutmut_5(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("XXSecret: XX")


def x__resolve_secret__mutmut_6(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("secret: ")


def x__resolve_secret__mutmut_7(args: argparse.Namespace) -> str:
    if args.secret is not None:
        return args.secret
    if args.secret_file is not None:
        return _read_text_from_file(args.secret_file)
    if args.secret_stdin:
        return _read_text_from_stdin()
    # Interactive fallback
    return getpass.getpass("SECRET: ")

x__resolve_secret__mutmut_mutants : ClassVar[MutantDict] = {
'x__resolve_secret__mutmut_1': x__resolve_secret__mutmut_1, 
    'x__resolve_secret__mutmut_2': x__resolve_secret__mutmut_2, 
    'x__resolve_secret__mutmut_3': x__resolve_secret__mutmut_3, 
    'x__resolve_secret__mutmut_4': x__resolve_secret__mutmut_4, 
    'x__resolve_secret__mutmut_5': x__resolve_secret__mutmut_5, 
    'x__resolve_secret__mutmut_6': x__resolve_secret__mutmut_6, 
    'x__resolve_secret__mutmut_7': x__resolve_secret__mutmut_7
}

def _resolve_secret(*args, **kwargs):
    result = _mutmut_trampoline(x__resolve_secret__mutmut_orig, x__resolve_secret__mutmut_mutants, args, kwargs)
    return result 

_resolve_secret.__signature__ = _mutmut_signature(x__resolve_secret__mutmut_orig)
x__resolve_secret__mutmut_orig.__name__ = 'x__resolve_secret'


def x__resolve_key__mutmut_orig(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_1(args: argparse.Namespace) -> str:
    if args.key is None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_2(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_3(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip(None)
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_4(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(None).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_5(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("XX\n\rXX")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_6(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip(None)
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_7(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("XX\n\rXX")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_8(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass(None)
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_9(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("XXKey: XX")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_10(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_11(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("KEY: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("Key: ")


def x__resolve_key__mutmut_12(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass(None)


def x__resolve_key__mutmut_13(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("XXKey: XX")


def x__resolve_key__mutmut_14(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("key: ")


def x__resolve_key__mutmut_15(args: argparse.Namespace) -> str:
    if args.key is not None:
        return args.key
    if args.key_file is not None:
        return _read_text_from_file(args.key_file).strip("\n\r")
    if args.key_stdin:
        return _read_text_from_stdin().strip("\n\r")
    if args.key_prompt:
        return getpass.getpass("Key: ")
    # If nothing provided, still prompt (safer default)
    return getpass.getpass("KEY: ")

x__resolve_key__mutmut_mutants : ClassVar[MutantDict] = {
'x__resolve_key__mutmut_1': x__resolve_key__mutmut_1, 
    'x__resolve_key__mutmut_2': x__resolve_key__mutmut_2, 
    'x__resolve_key__mutmut_3': x__resolve_key__mutmut_3, 
    'x__resolve_key__mutmut_4': x__resolve_key__mutmut_4, 
    'x__resolve_key__mutmut_5': x__resolve_key__mutmut_5, 
    'x__resolve_key__mutmut_6': x__resolve_key__mutmut_6, 
    'x__resolve_key__mutmut_7': x__resolve_key__mutmut_7, 
    'x__resolve_key__mutmut_8': x__resolve_key__mutmut_8, 
    'x__resolve_key__mutmut_9': x__resolve_key__mutmut_9, 
    'x__resolve_key__mutmut_10': x__resolve_key__mutmut_10, 
    'x__resolve_key__mutmut_11': x__resolve_key__mutmut_11, 
    'x__resolve_key__mutmut_12': x__resolve_key__mutmut_12, 
    'x__resolve_key__mutmut_13': x__resolve_key__mutmut_13, 
    'x__resolve_key__mutmut_14': x__resolve_key__mutmut_14, 
    'x__resolve_key__mutmut_15': x__resolve_key__mutmut_15
}

def _resolve_key(*args, **kwargs):
    result = _mutmut_trampoline(x__resolve_key__mutmut_orig, x__resolve_key__mutmut_mutants, args, kwargs)
    return result 

_resolve_key.__signature__ = _mutmut_signature(x__resolve_key__mutmut_orig)
x__resolve_key__mutmut_orig.__name__ = 'x__resolve_key'


# --------------------
# Subcommand handlers
# --------------------

def x_cmd_methods__mutmut_orig(_args: argparse.Namespace) -> int:
    for name in sorted(METHODS):
        print(name)
    return 0


# --------------------
# Subcommand handlers
# --------------------

def x_cmd_methods__mutmut_1(_args: argparse.Namespace) -> int:
    for name in sorted(None):
        print(name)
    return 0


# --------------------
# Subcommand handlers
# --------------------

def x_cmd_methods__mutmut_2(_args: argparse.Namespace) -> int:
    for name in sorted(METHODS):
        print(None)
    return 0


# --------------------
# Subcommand handlers
# --------------------

def x_cmd_methods__mutmut_3(_args: argparse.Namespace) -> int:
    for name in sorted(METHODS):
        print(name)
    return 1

x_cmd_methods__mutmut_mutants : ClassVar[MutantDict] = {
'x_cmd_methods__mutmut_1': x_cmd_methods__mutmut_1, 
    'x_cmd_methods__mutmut_2': x_cmd_methods__mutmut_2, 
    'x_cmd_methods__mutmut_3': x_cmd_methods__mutmut_3
}

def cmd_methods(*args, **kwargs):
    result = _mutmut_trampoline(x_cmd_methods__mutmut_orig, x_cmd_methods__mutmut_mutants, args, kwargs)
    return result 

cmd_methods.__signature__ = _mutmut_signature(x_cmd_methods__mutmut_orig)
x_cmd_methods__mutmut_orig.__name__ = 'x_cmd_methods'


def x_cmd_explore__mutmut_orig(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_1(args: argparse.Namespace) -> int:
    tree = None
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_2(args: argparse.Namespace) -> int:
    tree = explore_pdf(None)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_3(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(None, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_4(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, None, encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_5(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding=None) as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_6(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open("w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_7(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_8(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", ) as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_9(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "XXwXX", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_10(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "W", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_11(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="XXutf-8XX") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_12(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="UTF-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_13(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(None, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_14(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, None, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_15(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=None, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_16(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=None)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_17(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_18(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_19(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_20(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, )
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_21(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=3, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_22(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=True)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_23(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(None, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_24(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, None, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_25(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=None, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_26(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=None)
        print()
    return 0


def x_cmd_explore__mutmut_27(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_28(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, indent=2, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_29(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_30(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, )
        print()
    return 0


def x_cmd_explore__mutmut_31(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=3, ensure_ascii=False)
        print()
    return 0


def x_cmd_explore__mutmut_32(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=True)
        print()
    return 0


def x_cmd_explore__mutmut_33(args: argparse.Namespace) -> int:
    tree = explore_pdf(args.input)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(tree, fh, indent=2, ensure_ascii=False)
    else:
        json.dump(tree, sys.stdout, indent=2, ensure_ascii=False)
        print()
    return 1

x_cmd_explore__mutmut_mutants : ClassVar[MutantDict] = {
'x_cmd_explore__mutmut_1': x_cmd_explore__mutmut_1, 
    'x_cmd_explore__mutmut_2': x_cmd_explore__mutmut_2, 
    'x_cmd_explore__mutmut_3': x_cmd_explore__mutmut_3, 
    'x_cmd_explore__mutmut_4': x_cmd_explore__mutmut_4, 
    'x_cmd_explore__mutmut_5': x_cmd_explore__mutmut_5, 
    'x_cmd_explore__mutmut_6': x_cmd_explore__mutmut_6, 
    'x_cmd_explore__mutmut_7': x_cmd_explore__mutmut_7, 
    'x_cmd_explore__mutmut_8': x_cmd_explore__mutmut_8, 
    'x_cmd_explore__mutmut_9': x_cmd_explore__mutmut_9, 
    'x_cmd_explore__mutmut_10': x_cmd_explore__mutmut_10, 
    'x_cmd_explore__mutmut_11': x_cmd_explore__mutmut_11, 
    'x_cmd_explore__mutmut_12': x_cmd_explore__mutmut_12, 
    'x_cmd_explore__mutmut_13': x_cmd_explore__mutmut_13, 
    'x_cmd_explore__mutmut_14': x_cmd_explore__mutmut_14, 
    'x_cmd_explore__mutmut_15': x_cmd_explore__mutmut_15, 
    'x_cmd_explore__mutmut_16': x_cmd_explore__mutmut_16, 
    'x_cmd_explore__mutmut_17': x_cmd_explore__mutmut_17, 
    'x_cmd_explore__mutmut_18': x_cmd_explore__mutmut_18, 
    'x_cmd_explore__mutmut_19': x_cmd_explore__mutmut_19, 
    'x_cmd_explore__mutmut_20': x_cmd_explore__mutmut_20, 
    'x_cmd_explore__mutmut_21': x_cmd_explore__mutmut_21, 
    'x_cmd_explore__mutmut_22': x_cmd_explore__mutmut_22, 
    'x_cmd_explore__mutmut_23': x_cmd_explore__mutmut_23, 
    'x_cmd_explore__mutmut_24': x_cmd_explore__mutmut_24, 
    'x_cmd_explore__mutmut_25': x_cmd_explore__mutmut_25, 
    'x_cmd_explore__mutmut_26': x_cmd_explore__mutmut_26, 
    'x_cmd_explore__mutmut_27': x_cmd_explore__mutmut_27, 
    'x_cmd_explore__mutmut_28': x_cmd_explore__mutmut_28, 
    'x_cmd_explore__mutmut_29': x_cmd_explore__mutmut_29, 
    'x_cmd_explore__mutmut_30': x_cmd_explore__mutmut_30, 
    'x_cmd_explore__mutmut_31': x_cmd_explore__mutmut_31, 
    'x_cmd_explore__mutmut_32': x_cmd_explore__mutmut_32, 
    'x_cmd_explore__mutmut_33': x_cmd_explore__mutmut_33
}

def cmd_explore(*args, **kwargs):
    result = _mutmut_trampoline(x_cmd_explore__mutmut_orig, x_cmd_explore__mutmut_mutants, args, kwargs)
    return result 

cmd_explore.__signature__ = _mutmut_signature(x_cmd_explore__mutmut_orig)
x_cmd_explore__mutmut_orig.__name__ = 'x_cmd_explore'


def x_cmd_embed__mutmut_orig(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_1(args: argparse.Namespace) -> int:
    key = None
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_2(args: argparse.Namespace) -> int:
    key = _resolve_key(None)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_3(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = None
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_4(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(None)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_5(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print(None,key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_6(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",None)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_7(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print(key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_8(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_9(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("XXkey:XX",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_10(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("KEY:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_11(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_12(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=None,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_13(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=None, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_14(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=None):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_15(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_16(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_17(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, ):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_18(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(None)
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_19(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 6

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_20(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = None
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_21(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=None,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_22(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=None,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_23(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=None,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_24(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=None,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_25(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=None
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_26(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_27(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_28(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_29(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_30(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_31(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(None, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_32(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, None) as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_33(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open("wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_34(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, ) as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_35(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "XXwbXX") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_36(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "WB") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_37(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(None)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 0


def x_cmd_embed__mutmut_38(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(None)
    return 0


def x_cmd_embed__mutmut_39(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = _resolve_secret(args)
    print("key:",key)
    if not is_watermarking_applicable(method=args.method,pdf=args.input, position=args.position):
        print(f"Method {args.method} is not applicable on {args.output} at {args.position}.")
        return 5

    pdf_bytes = apply_watermark(
        method=args.method,
        pdf=args.input,
        secret=secret,
        key=key,
        position=args.position
    )
    with open(args.output, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"Wrote watermarked PDF -> {args.output}")
    return 1

x_cmd_embed__mutmut_mutants : ClassVar[MutantDict] = {
'x_cmd_embed__mutmut_1': x_cmd_embed__mutmut_1, 
    'x_cmd_embed__mutmut_2': x_cmd_embed__mutmut_2, 
    'x_cmd_embed__mutmut_3': x_cmd_embed__mutmut_3, 
    'x_cmd_embed__mutmut_4': x_cmd_embed__mutmut_4, 
    'x_cmd_embed__mutmut_5': x_cmd_embed__mutmut_5, 
    'x_cmd_embed__mutmut_6': x_cmd_embed__mutmut_6, 
    'x_cmd_embed__mutmut_7': x_cmd_embed__mutmut_7, 
    'x_cmd_embed__mutmut_8': x_cmd_embed__mutmut_8, 
    'x_cmd_embed__mutmut_9': x_cmd_embed__mutmut_9, 
    'x_cmd_embed__mutmut_10': x_cmd_embed__mutmut_10, 
    'x_cmd_embed__mutmut_11': x_cmd_embed__mutmut_11, 
    'x_cmd_embed__mutmut_12': x_cmd_embed__mutmut_12, 
    'x_cmd_embed__mutmut_13': x_cmd_embed__mutmut_13, 
    'x_cmd_embed__mutmut_14': x_cmd_embed__mutmut_14, 
    'x_cmd_embed__mutmut_15': x_cmd_embed__mutmut_15, 
    'x_cmd_embed__mutmut_16': x_cmd_embed__mutmut_16, 
    'x_cmd_embed__mutmut_17': x_cmd_embed__mutmut_17, 
    'x_cmd_embed__mutmut_18': x_cmd_embed__mutmut_18, 
    'x_cmd_embed__mutmut_19': x_cmd_embed__mutmut_19, 
    'x_cmd_embed__mutmut_20': x_cmd_embed__mutmut_20, 
    'x_cmd_embed__mutmut_21': x_cmd_embed__mutmut_21, 
    'x_cmd_embed__mutmut_22': x_cmd_embed__mutmut_22, 
    'x_cmd_embed__mutmut_23': x_cmd_embed__mutmut_23, 
    'x_cmd_embed__mutmut_24': x_cmd_embed__mutmut_24, 
    'x_cmd_embed__mutmut_25': x_cmd_embed__mutmut_25, 
    'x_cmd_embed__mutmut_26': x_cmd_embed__mutmut_26, 
    'x_cmd_embed__mutmut_27': x_cmd_embed__mutmut_27, 
    'x_cmd_embed__mutmut_28': x_cmd_embed__mutmut_28, 
    'x_cmd_embed__mutmut_29': x_cmd_embed__mutmut_29, 
    'x_cmd_embed__mutmut_30': x_cmd_embed__mutmut_30, 
    'x_cmd_embed__mutmut_31': x_cmd_embed__mutmut_31, 
    'x_cmd_embed__mutmut_32': x_cmd_embed__mutmut_32, 
    'x_cmd_embed__mutmut_33': x_cmd_embed__mutmut_33, 
    'x_cmd_embed__mutmut_34': x_cmd_embed__mutmut_34, 
    'x_cmd_embed__mutmut_35': x_cmd_embed__mutmut_35, 
    'x_cmd_embed__mutmut_36': x_cmd_embed__mutmut_36, 
    'x_cmd_embed__mutmut_37': x_cmd_embed__mutmut_37, 
    'x_cmd_embed__mutmut_38': x_cmd_embed__mutmut_38, 
    'x_cmd_embed__mutmut_39': x_cmd_embed__mutmut_39
}

def cmd_embed(*args, **kwargs):
    result = _mutmut_trampoline(x_cmd_embed__mutmut_orig, x_cmd_embed__mutmut_mutants, args, kwargs)
    return result 

cmd_embed.__signature__ = _mutmut_signature(x_cmd_embed__mutmut_orig)
x_cmd_embed__mutmut_orig.__name__ = 'x_cmd_embed'


def x_cmd_extract__mutmut_orig(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_1(args: argparse.Namespace) -> int:
    key = None
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_2(args: argparse.Namespace) -> int:
    key = _resolve_key(None)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_3(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = None
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_4(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=None, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_5(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=None, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_6(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=None)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_7(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_8(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_9(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_10(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(None, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_11(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, None, encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_12(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding=None) as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_13(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open("w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_14(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_15(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", ) as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_16(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "XXwXX", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_17(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "W", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_18(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="XXutf-8XX") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_19(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="UTF-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_20(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(None)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_21(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(None)
    else:
        print(secret)
    return 0


def x_cmd_extract__mutmut_22(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(None)
    return 0


def x_cmd_extract__mutmut_23(args: argparse.Namespace) -> int:
    key = _resolve_key(args)
    secret = read_watermark(method=args.method, pdf=args.input, key=key)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(secret)
        print(f"Wrote secret -> {args.out}")
    else:
        print(secret)
    return 1

x_cmd_extract__mutmut_mutants : ClassVar[MutantDict] = {
'x_cmd_extract__mutmut_1': x_cmd_extract__mutmut_1, 
    'x_cmd_extract__mutmut_2': x_cmd_extract__mutmut_2, 
    'x_cmd_extract__mutmut_3': x_cmd_extract__mutmut_3, 
    'x_cmd_extract__mutmut_4': x_cmd_extract__mutmut_4, 
    'x_cmd_extract__mutmut_5': x_cmd_extract__mutmut_5, 
    'x_cmd_extract__mutmut_6': x_cmd_extract__mutmut_6, 
    'x_cmd_extract__mutmut_7': x_cmd_extract__mutmut_7, 
    'x_cmd_extract__mutmut_8': x_cmd_extract__mutmut_8, 
    'x_cmd_extract__mutmut_9': x_cmd_extract__mutmut_9, 
    'x_cmd_extract__mutmut_10': x_cmd_extract__mutmut_10, 
    'x_cmd_extract__mutmut_11': x_cmd_extract__mutmut_11, 
    'x_cmd_extract__mutmut_12': x_cmd_extract__mutmut_12, 
    'x_cmd_extract__mutmut_13': x_cmd_extract__mutmut_13, 
    'x_cmd_extract__mutmut_14': x_cmd_extract__mutmut_14, 
    'x_cmd_extract__mutmut_15': x_cmd_extract__mutmut_15, 
    'x_cmd_extract__mutmut_16': x_cmd_extract__mutmut_16, 
    'x_cmd_extract__mutmut_17': x_cmd_extract__mutmut_17, 
    'x_cmd_extract__mutmut_18': x_cmd_extract__mutmut_18, 
    'x_cmd_extract__mutmut_19': x_cmd_extract__mutmut_19, 
    'x_cmd_extract__mutmut_20': x_cmd_extract__mutmut_20, 
    'x_cmd_extract__mutmut_21': x_cmd_extract__mutmut_21, 
    'x_cmd_extract__mutmut_22': x_cmd_extract__mutmut_22, 
    'x_cmd_extract__mutmut_23': x_cmd_extract__mutmut_23
}

def cmd_extract(*args, **kwargs):
    result = _mutmut_trampoline(x_cmd_extract__mutmut_orig, x_cmd_extract__mutmut_mutants, args, kwargs)
    return result 

cmd_extract.__signature__ = _mutmut_signature(x_cmd_extract__mutmut_orig)
x_cmd_extract__mutmut_orig.__name__ = 'x_cmd_extract'


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_orig() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_1() -> argparse.ArgumentParser:
    p = None
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_2() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=None,
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_3() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description=None
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_4() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_5() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_6() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="XXpdfwmXX",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_7() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="PDFWM",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_8() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="XXPDF watermarking utilities (embed/extract/explore)XX"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_9() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="pdf watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_10() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF WATERMARKING UTILITIES (EMBED/EXTRACT/EXPLORE)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_11() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument(None, action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_12() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action=None, version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_13() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=None)

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_14() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument(action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_15() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_16() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", )

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_17() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("XX--versionXX", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_18() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--VERSION", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_19() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="XXversionXX", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_20() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="VERSION", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_21() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = None

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_22() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest=None, required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_23() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=None)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_24() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_25() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", )

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_26() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="XXcmdXX", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_27() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="CMD", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_28() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=False)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_29() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = None
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_30() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser(None, help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_31() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help=None)
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_32() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser(help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_33() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", )
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_34() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("XXmethodsXX", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_35() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("METHODS", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_36() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="XXList available watermarking methodsXX")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_37() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="list available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_38() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="LIST AVAILABLE WATERMARKING METHODS")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_39() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=None)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_40() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = None
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_41() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        None,
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_42() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help=None
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_43() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_44() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_45() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "XXexploreXX",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_46() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "EXPLORE",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_47() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="XXExplore a PDF and print a JSON tree of nodesXX"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_48() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="explore a pdf and print a json tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_49() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="EXPLORE A PDF AND PRINT A JSON TREE OF NODES"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_50() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument(None, help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_51() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help=None)
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_52() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument(help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_53() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", )
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_54() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("XXinputXX", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_55() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("INPUT", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_56() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="XXInput PDF pathXX")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_57() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="input pdf path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_58() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="INPUT PDF PATH")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_59() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument(None, help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_60() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help=None)
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_61() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument(help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_62() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", )
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_63() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("XX--outXX", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_64() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--OUT", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_65() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="XXOutput JSON file (default: stdout)XX")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_66() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="output json file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_67() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="OUTPUT JSON FILE (DEFAULT: STDOUT)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_68() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=None)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_69() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = None
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_70() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser(None, help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_71() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help=None)
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_72() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser(help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_73() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", )
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_74() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("XXembedXX", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_75() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("EMBED", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_76() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="XXEmbed a secret into a PDFXX")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_77() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="embed a secret into a pdf")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_78() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="EMBED A SECRET INTO A PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_79() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument(None, help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_80() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help=None)
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_81() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument(help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_82() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", )
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_83() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("XXinputXX", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_84() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("INPUT", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_85() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="XXInput PDF pathXX")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_86() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="input pdf path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_87() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="INPUT PDF PATH")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_88() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument(None, help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_89() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help=None)
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_90() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument(help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_91() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", )
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_92() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("XXoutputXX", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_93() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("OUTPUT", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_94() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="XXOutput (watermarked) PDF pathXX")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_95() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="output (watermarked) pdf path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_96() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="OUTPUT (WATERMARKED) PDF PATH")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_97() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        None,
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_98() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default=None,
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_99() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help=None
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_100() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_101() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_102() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_103() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "XX--methodXX",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_104() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--METHOD",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_105() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="XXtoy-eofXX",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_106() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="TOY-EOF",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_107() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="XXWatermarking method name (default: toy-eof)XX"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_108() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_109() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="WATERMARKING METHOD NAME (DEFAULT: TOY-EOF)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_110() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument(None, help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_111() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help=None, default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_112() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument(help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_113() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_114() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", )

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_115() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("XX--positionXX", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_116() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--POSITION", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_117() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="XXOptional position hintXX", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_118() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_119() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="OPTIONAL POSITION HINT", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_120() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = None
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_121() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group(None)
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_122() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("XXsecret inputXX")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_123() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("SECRET INPUT")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_124() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument(None, help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_125() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help=None)
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_126() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument(help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_127() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", )
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_128() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("XX--secretXX", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_129() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--SECRET", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_130() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="XXSecret string to embedXX")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_131() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_132() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="SECRET STRING TO EMBED")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_133() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument(None, help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_134() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help=None)
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_135() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument(help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_136() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", )
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_137() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("XX--secret-fileXX", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_138() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--SECRET-FILE", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_139() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="XXRead secret from text fileXX")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_140() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_141() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="READ SECRET FROM TEXT FILE")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_142() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        None,
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_143() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action=None,
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_144() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help=None
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_145() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_146() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_147() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_148() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "XX--secret-stdinXX",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_149() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--SECRET-STDIN",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_150() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="XXstore_trueXX",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_151() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="STORE_TRUE",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_152() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="XXRead secret from stdinXX"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_153() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_154() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="READ SECRET FROM STDIN"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_155() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = None
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_156() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group(None)
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_157() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("XXkey inputXX")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_158() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("KEY INPUT")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_159() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument(None, help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_160() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help=None)
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_161() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument(help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_162() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", )
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_163() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("XX--keyXX", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_164() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--KEY", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_165() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="XXKey stringXX")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_166() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_167() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="KEY STRING")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_168() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument(None, help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_169() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help=None)
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_170() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument(help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_171() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", )
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_172() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("XX--key-fileXX", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_173() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--KEY-FILE", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_174() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="XXRead key from text fileXX")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_175() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_176() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="READ KEY FROM TEXT FILE")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_177() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument(None, action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_178() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action=None, help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_179() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help=None)
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_180() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument(action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_181() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_182() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", )
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_183() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("XX--key-stdinXX", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_184() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--KEY-STDIN", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_185() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="XXstore_trueXX", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_186() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="STORE_TRUE", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_187() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="XXRead key from stdinXX")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_188() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_189() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="READ KEY FROM STDIN")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_190() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument(None, action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_191() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action=None, help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_192() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help=None)

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_193() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument(action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_194() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_195() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", )

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_196() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("XX--key-promptXX", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_197() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--KEY-PROMPT", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_198() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="XXstore_trueXX", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_199() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="STORE_TRUE", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_200() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="XXPrompt for keyXX")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_201() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_202() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="PROMPT FOR KEY")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_203() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=None)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_204() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = None
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_205() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser(None, help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_206() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help=None)
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_207() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser(help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_208() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", )
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_209() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("XXextractXX", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_210() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("EXTRACT", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_211() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="XXExtract a secret from a PDFXX")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_212() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="extract a secret from a pdf")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_213() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="EXTRACT A SECRET FROM A PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_214() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument(None, help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_215() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help=None)
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_216() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument(help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_217() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", )
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_218() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("XXinputXX", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_219() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("INPUT", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_220() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="XXInput PDF path (possibly watermarked)XX")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_221() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="input pdf path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_222() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="INPUT PDF PATH (POSSIBLY WATERMARKED)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_223() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        None,
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_224() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default=None,
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_225() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help=None
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_226() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_227() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_228() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_229() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "XX--methodXX",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_230() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--METHOD",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_231() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="XXtoy-eofXX",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_232() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="TOY-EOF",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_233() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="XXWatermarking method name (default: toy-eof)XX"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_234() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_235() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="WATERMARKING METHOD NAME (DEFAULT: TOY-EOF)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_236() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = None
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_237() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group(None)
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_238() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("XXkey inputXX")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_239() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("KEY INPUT")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_240() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument(None, help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_241() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help=None)
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_242() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument(help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_243() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", )
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_244() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("XX--keyXX", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_245() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--KEY", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_246() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="XXKey stringXX")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_247() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_248() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="KEY STRING")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_249() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument(None, help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_250() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help=None)
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_251() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument(help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_252() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", )
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_253() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("XX--key-fileXX", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_254() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--KEY-FILE", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_255() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="XXRead key from text fileXX")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_256() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_257() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="READ KEY FROM TEXT FILE")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_258() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument(None, action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_259() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action=None, help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_260() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help=None)
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_261() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument(action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_262() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_263() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", )
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_264() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("XX--key-stdinXX", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_265() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--KEY-STDIN", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_266() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="XXstore_trueXX", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_267() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="STORE_TRUE", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_268() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="XXRead key from stdinXX")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_269() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_270() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="READ KEY FROM STDIN")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_271() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument(None, action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_272() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action=None, help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_273() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help=None)

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_274() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument(action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_275() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_276() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", )

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_277() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("XX--key-promptXX", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_278() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--KEY-PROMPT", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_279() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="XXstore_trueXX", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_280() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="STORE_TRUE", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_281() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="XXPrompt for keyXX")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_282() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_283() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="PROMPT FOR KEY")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_284() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument(None, help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_285() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help=None)

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_286() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument(help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_287() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", )

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_288() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("XX--outXX", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_289() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--OUT", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_290() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="XXWrite recovered secret to file (default: stdout)XX")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_291() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_292() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="WRITE RECOVERED SECRET TO FILE (DEFAULT: STDOUT)")

    p_extract.set_defaults(func=cmd_extract)

    return p


# --------------------
# Argument parser
# --------------------

def x_build_parser__mutmut_293() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pdfwm",
        description="PDF watermarking utilities (embed/extract/explore)"
    )
    p.add_argument("--version", action="version", version=f"pdfwm {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # methods
    p_methods = sub.add_parser("methods", help="List available watermarking methods")
    p_methods.set_defaults(func=cmd_methods)

    # explore
    p_explore = sub.add_parser(
        "explore",
        help="Explore a PDF and print a JSON tree of nodes"
    )
    p_explore.add_argument("input", help="Input PDF path")
    p_explore.add_argument("--out", help="Output JSON file (default: stdout)")
    p_explore.set_defaults(func=cmd_explore)

    # embed
    p_embed = sub.add_parser("embed", help="Embed a secret into a PDF")
    p_embed.add_argument("input", help="Input PDF path")
    p_embed.add_argument("output", help="Output (watermarked) PDF path")
    p_embed.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )
    p_embed.add_argument("--position", help="Optional position hint", default=None)

    g_secret = p_embed.add_argument_group("secret input")
    g_secret.add_argument("--secret", help="Secret string to embed")
    g_secret.add_argument("--secret-file", help="Read secret from text file")
    g_secret.add_argument(
        "--secret-stdin",
        action="store_true",
        help="Read secret from stdin"
    )

    g_key = p_embed.add_argument_group("key input")
    g_key.add_argument("--key", help="Key string")
    g_key.add_argument("--key-file", help="Read key from text file")
    g_key.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_embed.set_defaults(func=cmd_embed)

    # extract
    p_extract = sub.add_parser("extract", help="Extract a secret from a PDF")
    p_extract.add_argument("input", help="Input PDF path (possibly watermarked)")
    p_extract.add_argument(
        "--method",
        default="toy-eof",
        help="Watermarking method name (default: toy-eof)"
    )

    g_key2 = p_extract.add_argument_group("key input")
    g_key2.add_argument("--key", help="Key string")
    g_key2.add_argument("--key-file", help="Read key from text file")
    g_key2.add_argument("--key-stdin", action="store_true", help="Read key from stdin")
    g_key2.add_argument("--key-prompt", action="store_true", help="Prompt for key")

    p_extract.add_argument("--out", help="Write recovered secret to file (default: stdout)")

    p_extract.set_defaults(func=None)

    return p

x_build_parser__mutmut_mutants : ClassVar[MutantDict] = {
'x_build_parser__mutmut_1': x_build_parser__mutmut_1, 
    'x_build_parser__mutmut_2': x_build_parser__mutmut_2, 
    'x_build_parser__mutmut_3': x_build_parser__mutmut_3, 
    'x_build_parser__mutmut_4': x_build_parser__mutmut_4, 
    'x_build_parser__mutmut_5': x_build_parser__mutmut_5, 
    'x_build_parser__mutmut_6': x_build_parser__mutmut_6, 
    'x_build_parser__mutmut_7': x_build_parser__mutmut_7, 
    'x_build_parser__mutmut_8': x_build_parser__mutmut_8, 
    'x_build_parser__mutmut_9': x_build_parser__mutmut_9, 
    'x_build_parser__mutmut_10': x_build_parser__mutmut_10, 
    'x_build_parser__mutmut_11': x_build_parser__mutmut_11, 
    'x_build_parser__mutmut_12': x_build_parser__mutmut_12, 
    'x_build_parser__mutmut_13': x_build_parser__mutmut_13, 
    'x_build_parser__mutmut_14': x_build_parser__mutmut_14, 
    'x_build_parser__mutmut_15': x_build_parser__mutmut_15, 
    'x_build_parser__mutmut_16': x_build_parser__mutmut_16, 
    'x_build_parser__mutmut_17': x_build_parser__mutmut_17, 
    'x_build_parser__mutmut_18': x_build_parser__mutmut_18, 
    'x_build_parser__mutmut_19': x_build_parser__mutmut_19, 
    'x_build_parser__mutmut_20': x_build_parser__mutmut_20, 
    'x_build_parser__mutmut_21': x_build_parser__mutmut_21, 
    'x_build_parser__mutmut_22': x_build_parser__mutmut_22, 
    'x_build_parser__mutmut_23': x_build_parser__mutmut_23, 
    'x_build_parser__mutmut_24': x_build_parser__mutmut_24, 
    'x_build_parser__mutmut_25': x_build_parser__mutmut_25, 
    'x_build_parser__mutmut_26': x_build_parser__mutmut_26, 
    'x_build_parser__mutmut_27': x_build_parser__mutmut_27, 
    'x_build_parser__mutmut_28': x_build_parser__mutmut_28, 
    'x_build_parser__mutmut_29': x_build_parser__mutmut_29, 
    'x_build_parser__mutmut_30': x_build_parser__mutmut_30, 
    'x_build_parser__mutmut_31': x_build_parser__mutmut_31, 
    'x_build_parser__mutmut_32': x_build_parser__mutmut_32, 
    'x_build_parser__mutmut_33': x_build_parser__mutmut_33, 
    'x_build_parser__mutmut_34': x_build_parser__mutmut_34, 
    'x_build_parser__mutmut_35': x_build_parser__mutmut_35, 
    'x_build_parser__mutmut_36': x_build_parser__mutmut_36, 
    'x_build_parser__mutmut_37': x_build_parser__mutmut_37, 
    'x_build_parser__mutmut_38': x_build_parser__mutmut_38, 
    'x_build_parser__mutmut_39': x_build_parser__mutmut_39, 
    'x_build_parser__mutmut_40': x_build_parser__mutmut_40, 
    'x_build_parser__mutmut_41': x_build_parser__mutmut_41, 
    'x_build_parser__mutmut_42': x_build_parser__mutmut_42, 
    'x_build_parser__mutmut_43': x_build_parser__mutmut_43, 
    'x_build_parser__mutmut_44': x_build_parser__mutmut_44, 
    'x_build_parser__mutmut_45': x_build_parser__mutmut_45, 
    'x_build_parser__mutmut_46': x_build_parser__mutmut_46, 
    'x_build_parser__mutmut_47': x_build_parser__mutmut_47, 
    'x_build_parser__mutmut_48': x_build_parser__mutmut_48, 
    'x_build_parser__mutmut_49': x_build_parser__mutmut_49, 
    'x_build_parser__mutmut_50': x_build_parser__mutmut_50, 
    'x_build_parser__mutmut_51': x_build_parser__mutmut_51, 
    'x_build_parser__mutmut_52': x_build_parser__mutmut_52, 
    'x_build_parser__mutmut_53': x_build_parser__mutmut_53, 
    'x_build_parser__mutmut_54': x_build_parser__mutmut_54, 
    'x_build_parser__mutmut_55': x_build_parser__mutmut_55, 
    'x_build_parser__mutmut_56': x_build_parser__mutmut_56, 
    'x_build_parser__mutmut_57': x_build_parser__mutmut_57, 
    'x_build_parser__mutmut_58': x_build_parser__mutmut_58, 
    'x_build_parser__mutmut_59': x_build_parser__mutmut_59, 
    'x_build_parser__mutmut_60': x_build_parser__mutmut_60, 
    'x_build_parser__mutmut_61': x_build_parser__mutmut_61, 
    'x_build_parser__mutmut_62': x_build_parser__mutmut_62, 
    'x_build_parser__mutmut_63': x_build_parser__mutmut_63, 
    'x_build_parser__mutmut_64': x_build_parser__mutmut_64, 
    'x_build_parser__mutmut_65': x_build_parser__mutmut_65, 
    'x_build_parser__mutmut_66': x_build_parser__mutmut_66, 
    'x_build_parser__mutmut_67': x_build_parser__mutmut_67, 
    'x_build_parser__mutmut_68': x_build_parser__mutmut_68, 
    'x_build_parser__mutmut_69': x_build_parser__mutmut_69, 
    'x_build_parser__mutmut_70': x_build_parser__mutmut_70, 
    'x_build_parser__mutmut_71': x_build_parser__mutmut_71, 
    'x_build_parser__mutmut_72': x_build_parser__mutmut_72, 
    'x_build_parser__mutmut_73': x_build_parser__mutmut_73, 
    'x_build_parser__mutmut_74': x_build_parser__mutmut_74, 
    'x_build_parser__mutmut_75': x_build_parser__mutmut_75, 
    'x_build_parser__mutmut_76': x_build_parser__mutmut_76, 
    'x_build_parser__mutmut_77': x_build_parser__mutmut_77, 
    'x_build_parser__mutmut_78': x_build_parser__mutmut_78, 
    'x_build_parser__mutmut_79': x_build_parser__mutmut_79, 
    'x_build_parser__mutmut_80': x_build_parser__mutmut_80, 
    'x_build_parser__mutmut_81': x_build_parser__mutmut_81, 
    'x_build_parser__mutmut_82': x_build_parser__mutmut_82, 
    'x_build_parser__mutmut_83': x_build_parser__mutmut_83, 
    'x_build_parser__mutmut_84': x_build_parser__mutmut_84, 
    'x_build_parser__mutmut_85': x_build_parser__mutmut_85, 
    'x_build_parser__mutmut_86': x_build_parser__mutmut_86, 
    'x_build_parser__mutmut_87': x_build_parser__mutmut_87, 
    'x_build_parser__mutmut_88': x_build_parser__mutmut_88, 
    'x_build_parser__mutmut_89': x_build_parser__mutmut_89, 
    'x_build_parser__mutmut_90': x_build_parser__mutmut_90, 
    'x_build_parser__mutmut_91': x_build_parser__mutmut_91, 
    'x_build_parser__mutmut_92': x_build_parser__mutmut_92, 
    'x_build_parser__mutmut_93': x_build_parser__mutmut_93, 
    'x_build_parser__mutmut_94': x_build_parser__mutmut_94, 
    'x_build_parser__mutmut_95': x_build_parser__mutmut_95, 
    'x_build_parser__mutmut_96': x_build_parser__mutmut_96, 
    'x_build_parser__mutmut_97': x_build_parser__mutmut_97, 
    'x_build_parser__mutmut_98': x_build_parser__mutmut_98, 
    'x_build_parser__mutmut_99': x_build_parser__mutmut_99, 
    'x_build_parser__mutmut_100': x_build_parser__mutmut_100, 
    'x_build_parser__mutmut_101': x_build_parser__mutmut_101, 
    'x_build_parser__mutmut_102': x_build_parser__mutmut_102, 
    'x_build_parser__mutmut_103': x_build_parser__mutmut_103, 
    'x_build_parser__mutmut_104': x_build_parser__mutmut_104, 
    'x_build_parser__mutmut_105': x_build_parser__mutmut_105, 
    'x_build_parser__mutmut_106': x_build_parser__mutmut_106, 
    'x_build_parser__mutmut_107': x_build_parser__mutmut_107, 
    'x_build_parser__mutmut_108': x_build_parser__mutmut_108, 
    'x_build_parser__mutmut_109': x_build_parser__mutmut_109, 
    'x_build_parser__mutmut_110': x_build_parser__mutmut_110, 
    'x_build_parser__mutmut_111': x_build_parser__mutmut_111, 
    'x_build_parser__mutmut_112': x_build_parser__mutmut_112, 
    'x_build_parser__mutmut_113': x_build_parser__mutmut_113, 
    'x_build_parser__mutmut_114': x_build_parser__mutmut_114, 
    'x_build_parser__mutmut_115': x_build_parser__mutmut_115, 
    'x_build_parser__mutmut_116': x_build_parser__mutmut_116, 
    'x_build_parser__mutmut_117': x_build_parser__mutmut_117, 
    'x_build_parser__mutmut_118': x_build_parser__mutmut_118, 
    'x_build_parser__mutmut_119': x_build_parser__mutmut_119, 
    'x_build_parser__mutmut_120': x_build_parser__mutmut_120, 
    'x_build_parser__mutmut_121': x_build_parser__mutmut_121, 
    'x_build_parser__mutmut_122': x_build_parser__mutmut_122, 
    'x_build_parser__mutmut_123': x_build_parser__mutmut_123, 
    'x_build_parser__mutmut_124': x_build_parser__mutmut_124, 
    'x_build_parser__mutmut_125': x_build_parser__mutmut_125, 
    'x_build_parser__mutmut_126': x_build_parser__mutmut_126, 
    'x_build_parser__mutmut_127': x_build_parser__mutmut_127, 
    'x_build_parser__mutmut_128': x_build_parser__mutmut_128, 
    'x_build_parser__mutmut_129': x_build_parser__mutmut_129, 
    'x_build_parser__mutmut_130': x_build_parser__mutmut_130, 
    'x_build_parser__mutmut_131': x_build_parser__mutmut_131, 
    'x_build_parser__mutmut_132': x_build_parser__mutmut_132, 
    'x_build_parser__mutmut_133': x_build_parser__mutmut_133, 
    'x_build_parser__mutmut_134': x_build_parser__mutmut_134, 
    'x_build_parser__mutmut_135': x_build_parser__mutmut_135, 
    'x_build_parser__mutmut_136': x_build_parser__mutmut_136, 
    'x_build_parser__mutmut_137': x_build_parser__mutmut_137, 
    'x_build_parser__mutmut_138': x_build_parser__mutmut_138, 
    'x_build_parser__mutmut_139': x_build_parser__mutmut_139, 
    'x_build_parser__mutmut_140': x_build_parser__mutmut_140, 
    'x_build_parser__mutmut_141': x_build_parser__mutmut_141, 
    'x_build_parser__mutmut_142': x_build_parser__mutmut_142, 
    'x_build_parser__mutmut_143': x_build_parser__mutmut_143, 
    'x_build_parser__mutmut_144': x_build_parser__mutmut_144, 
    'x_build_parser__mutmut_145': x_build_parser__mutmut_145, 
    'x_build_parser__mutmut_146': x_build_parser__mutmut_146, 
    'x_build_parser__mutmut_147': x_build_parser__mutmut_147, 
    'x_build_parser__mutmut_148': x_build_parser__mutmut_148, 
    'x_build_parser__mutmut_149': x_build_parser__mutmut_149, 
    'x_build_parser__mutmut_150': x_build_parser__mutmut_150, 
    'x_build_parser__mutmut_151': x_build_parser__mutmut_151, 
    'x_build_parser__mutmut_152': x_build_parser__mutmut_152, 
    'x_build_parser__mutmut_153': x_build_parser__mutmut_153, 
    'x_build_parser__mutmut_154': x_build_parser__mutmut_154, 
    'x_build_parser__mutmut_155': x_build_parser__mutmut_155, 
    'x_build_parser__mutmut_156': x_build_parser__mutmut_156, 
    'x_build_parser__mutmut_157': x_build_parser__mutmut_157, 
    'x_build_parser__mutmut_158': x_build_parser__mutmut_158, 
    'x_build_parser__mutmut_159': x_build_parser__mutmut_159, 
    'x_build_parser__mutmut_160': x_build_parser__mutmut_160, 
    'x_build_parser__mutmut_161': x_build_parser__mutmut_161, 
    'x_build_parser__mutmut_162': x_build_parser__mutmut_162, 
    'x_build_parser__mutmut_163': x_build_parser__mutmut_163, 
    'x_build_parser__mutmut_164': x_build_parser__mutmut_164, 
    'x_build_parser__mutmut_165': x_build_parser__mutmut_165, 
    'x_build_parser__mutmut_166': x_build_parser__mutmut_166, 
    'x_build_parser__mutmut_167': x_build_parser__mutmut_167, 
    'x_build_parser__mutmut_168': x_build_parser__mutmut_168, 
    'x_build_parser__mutmut_169': x_build_parser__mutmut_169, 
    'x_build_parser__mutmut_170': x_build_parser__mutmut_170, 
    'x_build_parser__mutmut_171': x_build_parser__mutmut_171, 
    'x_build_parser__mutmut_172': x_build_parser__mutmut_172, 
    'x_build_parser__mutmut_173': x_build_parser__mutmut_173, 
    'x_build_parser__mutmut_174': x_build_parser__mutmut_174, 
    'x_build_parser__mutmut_175': x_build_parser__mutmut_175, 
    'x_build_parser__mutmut_176': x_build_parser__mutmut_176, 
    'x_build_parser__mutmut_177': x_build_parser__mutmut_177, 
    'x_build_parser__mutmut_178': x_build_parser__mutmut_178, 
    'x_build_parser__mutmut_179': x_build_parser__mutmut_179, 
    'x_build_parser__mutmut_180': x_build_parser__mutmut_180, 
    'x_build_parser__mutmut_181': x_build_parser__mutmut_181, 
    'x_build_parser__mutmut_182': x_build_parser__mutmut_182, 
    'x_build_parser__mutmut_183': x_build_parser__mutmut_183, 
    'x_build_parser__mutmut_184': x_build_parser__mutmut_184, 
    'x_build_parser__mutmut_185': x_build_parser__mutmut_185, 
    'x_build_parser__mutmut_186': x_build_parser__mutmut_186, 
    'x_build_parser__mutmut_187': x_build_parser__mutmut_187, 
    'x_build_parser__mutmut_188': x_build_parser__mutmut_188, 
    'x_build_parser__mutmut_189': x_build_parser__mutmut_189, 
    'x_build_parser__mutmut_190': x_build_parser__mutmut_190, 
    'x_build_parser__mutmut_191': x_build_parser__mutmut_191, 
    'x_build_parser__mutmut_192': x_build_parser__mutmut_192, 
    'x_build_parser__mutmut_193': x_build_parser__mutmut_193, 
    'x_build_parser__mutmut_194': x_build_parser__mutmut_194, 
    'x_build_parser__mutmut_195': x_build_parser__mutmut_195, 
    'x_build_parser__mutmut_196': x_build_parser__mutmut_196, 
    'x_build_parser__mutmut_197': x_build_parser__mutmut_197, 
    'x_build_parser__mutmut_198': x_build_parser__mutmut_198, 
    'x_build_parser__mutmut_199': x_build_parser__mutmut_199, 
    'x_build_parser__mutmut_200': x_build_parser__mutmut_200, 
    'x_build_parser__mutmut_201': x_build_parser__mutmut_201, 
    'x_build_parser__mutmut_202': x_build_parser__mutmut_202, 
    'x_build_parser__mutmut_203': x_build_parser__mutmut_203, 
    'x_build_parser__mutmut_204': x_build_parser__mutmut_204, 
    'x_build_parser__mutmut_205': x_build_parser__mutmut_205, 
    'x_build_parser__mutmut_206': x_build_parser__mutmut_206, 
    'x_build_parser__mutmut_207': x_build_parser__mutmut_207, 
    'x_build_parser__mutmut_208': x_build_parser__mutmut_208, 
    'x_build_parser__mutmut_209': x_build_parser__mutmut_209, 
    'x_build_parser__mutmut_210': x_build_parser__mutmut_210, 
    'x_build_parser__mutmut_211': x_build_parser__mutmut_211, 
    'x_build_parser__mutmut_212': x_build_parser__mutmut_212, 
    'x_build_parser__mutmut_213': x_build_parser__mutmut_213, 
    'x_build_parser__mutmut_214': x_build_parser__mutmut_214, 
    'x_build_parser__mutmut_215': x_build_parser__mutmut_215, 
    'x_build_parser__mutmut_216': x_build_parser__mutmut_216, 
    'x_build_parser__mutmut_217': x_build_parser__mutmut_217, 
    'x_build_parser__mutmut_218': x_build_parser__mutmut_218, 
    'x_build_parser__mutmut_219': x_build_parser__mutmut_219, 
    'x_build_parser__mutmut_220': x_build_parser__mutmut_220, 
    'x_build_parser__mutmut_221': x_build_parser__mutmut_221, 
    'x_build_parser__mutmut_222': x_build_parser__mutmut_222, 
    'x_build_parser__mutmut_223': x_build_parser__mutmut_223, 
    'x_build_parser__mutmut_224': x_build_parser__mutmut_224, 
    'x_build_parser__mutmut_225': x_build_parser__mutmut_225, 
    'x_build_parser__mutmut_226': x_build_parser__mutmut_226, 
    'x_build_parser__mutmut_227': x_build_parser__mutmut_227, 
    'x_build_parser__mutmut_228': x_build_parser__mutmut_228, 
    'x_build_parser__mutmut_229': x_build_parser__mutmut_229, 
    'x_build_parser__mutmut_230': x_build_parser__mutmut_230, 
    'x_build_parser__mutmut_231': x_build_parser__mutmut_231, 
    'x_build_parser__mutmut_232': x_build_parser__mutmut_232, 
    'x_build_parser__mutmut_233': x_build_parser__mutmut_233, 
    'x_build_parser__mutmut_234': x_build_parser__mutmut_234, 
    'x_build_parser__mutmut_235': x_build_parser__mutmut_235, 
    'x_build_parser__mutmut_236': x_build_parser__mutmut_236, 
    'x_build_parser__mutmut_237': x_build_parser__mutmut_237, 
    'x_build_parser__mutmut_238': x_build_parser__mutmut_238, 
    'x_build_parser__mutmut_239': x_build_parser__mutmut_239, 
    'x_build_parser__mutmut_240': x_build_parser__mutmut_240, 
    'x_build_parser__mutmut_241': x_build_parser__mutmut_241, 
    'x_build_parser__mutmut_242': x_build_parser__mutmut_242, 
    'x_build_parser__mutmut_243': x_build_parser__mutmut_243, 
    'x_build_parser__mutmut_244': x_build_parser__mutmut_244, 
    'x_build_parser__mutmut_245': x_build_parser__mutmut_245, 
    'x_build_parser__mutmut_246': x_build_parser__mutmut_246, 
    'x_build_parser__mutmut_247': x_build_parser__mutmut_247, 
    'x_build_parser__mutmut_248': x_build_parser__mutmut_248, 
    'x_build_parser__mutmut_249': x_build_parser__mutmut_249, 
    'x_build_parser__mutmut_250': x_build_parser__mutmut_250, 
    'x_build_parser__mutmut_251': x_build_parser__mutmut_251, 
    'x_build_parser__mutmut_252': x_build_parser__mutmut_252, 
    'x_build_parser__mutmut_253': x_build_parser__mutmut_253, 
    'x_build_parser__mutmut_254': x_build_parser__mutmut_254, 
    'x_build_parser__mutmut_255': x_build_parser__mutmut_255, 
    'x_build_parser__mutmut_256': x_build_parser__mutmut_256, 
    'x_build_parser__mutmut_257': x_build_parser__mutmut_257, 
    'x_build_parser__mutmut_258': x_build_parser__mutmut_258, 
    'x_build_parser__mutmut_259': x_build_parser__mutmut_259, 
    'x_build_parser__mutmut_260': x_build_parser__mutmut_260, 
    'x_build_parser__mutmut_261': x_build_parser__mutmut_261, 
    'x_build_parser__mutmut_262': x_build_parser__mutmut_262, 
    'x_build_parser__mutmut_263': x_build_parser__mutmut_263, 
    'x_build_parser__mutmut_264': x_build_parser__mutmut_264, 
    'x_build_parser__mutmut_265': x_build_parser__mutmut_265, 
    'x_build_parser__mutmut_266': x_build_parser__mutmut_266, 
    'x_build_parser__mutmut_267': x_build_parser__mutmut_267, 
    'x_build_parser__mutmut_268': x_build_parser__mutmut_268, 
    'x_build_parser__mutmut_269': x_build_parser__mutmut_269, 
    'x_build_parser__mutmut_270': x_build_parser__mutmut_270, 
    'x_build_parser__mutmut_271': x_build_parser__mutmut_271, 
    'x_build_parser__mutmut_272': x_build_parser__mutmut_272, 
    'x_build_parser__mutmut_273': x_build_parser__mutmut_273, 
    'x_build_parser__mutmut_274': x_build_parser__mutmut_274, 
    'x_build_parser__mutmut_275': x_build_parser__mutmut_275, 
    'x_build_parser__mutmut_276': x_build_parser__mutmut_276, 
    'x_build_parser__mutmut_277': x_build_parser__mutmut_277, 
    'x_build_parser__mutmut_278': x_build_parser__mutmut_278, 
    'x_build_parser__mutmut_279': x_build_parser__mutmut_279, 
    'x_build_parser__mutmut_280': x_build_parser__mutmut_280, 
    'x_build_parser__mutmut_281': x_build_parser__mutmut_281, 
    'x_build_parser__mutmut_282': x_build_parser__mutmut_282, 
    'x_build_parser__mutmut_283': x_build_parser__mutmut_283, 
    'x_build_parser__mutmut_284': x_build_parser__mutmut_284, 
    'x_build_parser__mutmut_285': x_build_parser__mutmut_285, 
    'x_build_parser__mutmut_286': x_build_parser__mutmut_286, 
    'x_build_parser__mutmut_287': x_build_parser__mutmut_287, 
    'x_build_parser__mutmut_288': x_build_parser__mutmut_288, 
    'x_build_parser__mutmut_289': x_build_parser__mutmut_289, 
    'x_build_parser__mutmut_290': x_build_parser__mutmut_290, 
    'x_build_parser__mutmut_291': x_build_parser__mutmut_291, 
    'x_build_parser__mutmut_292': x_build_parser__mutmut_292, 
    'x_build_parser__mutmut_293': x_build_parser__mutmut_293
}

def build_parser(*args, **kwargs):
    result = _mutmut_trampoline(x_build_parser__mutmut_orig, x_build_parser__mutmut_mutants, args, kwargs)
    return result 

build_parser.__signature__ = _mutmut_signature(x_build_parser__mutmut_orig)
x_build_parser__mutmut_orig.__name__ = 'x_build_parser'


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_orig(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_1(argv: Optional[Iterable[str]] = None) -> int:
    parser = None
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_2(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = None

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_3(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_4(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(None) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_5(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_6(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(None)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_7(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(None))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_8(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(None, file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_9(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=None)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_10(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_11(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", )
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_12(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_13(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(None, file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_14(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=None)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_15(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_16(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", )
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_17(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_18(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(None, file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_19(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=None)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_20(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_21(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", )
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_22(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 4
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_23(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(None, file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_24(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=None)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_25(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_26(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", )
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_27(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 5
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_28(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(None, file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_29(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=None)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_30(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(file=sys.stderr)
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_31(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", )
        return 5


# --------------------
# Entrypoint
# --------------------

def x_main__mutmut_32(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        return int(args.func(args))
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SecretNotFoundError as e:
        print(f"secret not found: {e}", file=sys.stderr)
        return 3
    except InvalidKeyError as e:
        print(f"invalid key: {e}", file=sys.stderr)
        return 4
    except WatermarkingError as e:
        print(f"watermarking error: {e}", file=sys.stderr)
        return 6

x_main__mutmut_mutants : ClassVar[MutantDict] = {
'x_main__mutmut_1': x_main__mutmut_1, 
    'x_main__mutmut_2': x_main__mutmut_2, 
    'x_main__mutmut_3': x_main__mutmut_3, 
    'x_main__mutmut_4': x_main__mutmut_4, 
    'x_main__mutmut_5': x_main__mutmut_5, 
    'x_main__mutmut_6': x_main__mutmut_6, 
    'x_main__mutmut_7': x_main__mutmut_7, 
    'x_main__mutmut_8': x_main__mutmut_8, 
    'x_main__mutmut_9': x_main__mutmut_9, 
    'x_main__mutmut_10': x_main__mutmut_10, 
    'x_main__mutmut_11': x_main__mutmut_11, 
    'x_main__mutmut_12': x_main__mutmut_12, 
    'x_main__mutmut_13': x_main__mutmut_13, 
    'x_main__mutmut_14': x_main__mutmut_14, 
    'x_main__mutmut_15': x_main__mutmut_15, 
    'x_main__mutmut_16': x_main__mutmut_16, 
    'x_main__mutmut_17': x_main__mutmut_17, 
    'x_main__mutmut_18': x_main__mutmut_18, 
    'x_main__mutmut_19': x_main__mutmut_19, 
    'x_main__mutmut_20': x_main__mutmut_20, 
    'x_main__mutmut_21': x_main__mutmut_21, 
    'x_main__mutmut_22': x_main__mutmut_22, 
    'x_main__mutmut_23': x_main__mutmut_23, 
    'x_main__mutmut_24': x_main__mutmut_24, 
    'x_main__mutmut_25': x_main__mutmut_25, 
    'x_main__mutmut_26': x_main__mutmut_26, 
    'x_main__mutmut_27': x_main__mutmut_27, 
    'x_main__mutmut_28': x_main__mutmut_28, 
    'x_main__mutmut_29': x_main__mutmut_29, 
    'x_main__mutmut_30': x_main__mutmut_30, 
    'x_main__mutmut_31': x_main__mutmut_31, 
    'x_main__mutmut_32': x_main__mutmut_32
}

def main(*args, **kwargs):
    result = _mutmut_trampoline(x_main__mutmut_orig, x_main__mutmut_mutants, args, kwargs)
    return result 

main.__signature__ = _mutmut_signature(x_main__mutmut_orig)
x_main__mutmut_orig.__name__ = 'x_main'


if __name__ == "__main__":
    raise SystemExit(main())

