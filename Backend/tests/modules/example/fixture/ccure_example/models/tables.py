"""A table, in the module's own schema and on the module's own MetaData."""

from sqlalchemy import Column, Integer, MetaData, String, Table

metadata = MetaData(schema="example")

example_item = Table(
    "example_item",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("label", String(50), nullable=False),
)
