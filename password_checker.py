"""
password_checker.py - CLI terminal interface for Password Strength Checker.

Interactively evaluates passwords using the core analysis engine in checker_core.py.
Uses standard library modules only.
"""

import sys
from checker_core import (
    calculate_entropy,
    calculate_score,
    estimate_crack_time,
    get_feedback,
    get_strength_rating,
    get_suggestions,
)


def print_banner() -> None:
    """Print the application welcome banner."""
    print("=" * 60)
    print("           PASSWORD STRENGTH CHECKER (CLI)")
    print("=" * 60)
    print("Enter any password to evaluate its strength.")
    print("Type 'exit' to quit the application.\n")


def display_results(password: str) -> None:
    """Evaluate and display results for the given password."""
    score = calculate_score(password)
    rating = get_strength_rating(score)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    feedback_items = get_feedback(password)
    suggestions = get_suggestions(password)

    print("\n" + "-" * 60)
    print("ANALYSIS RESULTS:")
    print("-" * 60)
    print(f"  Strength Rating    : {rating}")
    print(f"  Overall Score      : {score}/100")
    print(f"  Entropy            : {entropy} bits")
    print(f"  Est. Crack Time    : {crack_time}")
    print("-" * 60)

    print("Issues & Feedback:")
    for item in feedback_items:
        print(f"  [!] {item}")

    print("\nSuggestions for Improvement:")
    for tip in suggestions:
        print(f"  [*] {tip}")

    print("-" * 60)


def main() -> None:
    """Main CLI interaction loop."""
    print_banner()

    try:
        while True:
            password = input("Enter password (or 'exit' to quit): ")

            # Check for exit command
            if password.strip().lower() == "exit":
                print("\nExiting Password Strength Checker. Stay secure!")
                break

            # Handle empty input gracefully
            if not password:
                print(">> Warning: Input was empty. Please type a password.\n")
                continue

            display_results(password)
            print()
    except (KeyboardInterrupt, EOFError):
        print("\n\nSession terminated. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
