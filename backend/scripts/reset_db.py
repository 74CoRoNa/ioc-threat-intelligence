import argparse

from app.core.database import Base, engine, initialize_database


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset the CyberIP Analyzer database.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm that all locally stored investigations may be deleted.",
    )
    args = parser.parse_args()
    if not args.yes:
        parser.error("Pass --yes to confirm the destructive reset.")
    Base.metadata.drop_all(bind=engine)
    initialize_database()
    print("Database reset complete.")


if __name__ == "__main__":
    main()

