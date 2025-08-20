#!/usr/bin/env python3
"""Enumerate MongoDB without authentication."""
from pymongo import MongoClient
import os

db_host = os.environ.get("MONGO_HOST", "my5gc-mongo.open5gs.svc.cluster.local")
client = MongoClient(f"mongodb://{db_host}:27017")
print("Databases:", client.list_database_names())
for db_name in client.list_database_names():
    db = client[db_name]
    print("Collections in", db_name, ":", db.list_collection_names()) 