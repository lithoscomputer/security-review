"""Deliberately vulnerable fixture used only to verify the Fabro workflow."""

import os


def run_report() -> None:
    command = input("Report command: ")
    os.system(command)
