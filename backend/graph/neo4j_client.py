"""
RepoGuard — Neo4j Client.

Handles the connection to the Neo4j database instances.
"""

import os
import logging
from contextlib import contextmanager
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
# Support both NEO4J_USERNAME (Aura default) and NEO4J_USER
NEO4J_USER = os.getenv("NEO4J_USERNAME") or os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

driver = None

def get_driver():
    global driver
    if driver is None:
        try:
            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            logger.info("Neo4j driver initialised.")
        except Exception as e:
            logger.error(f"Could not connect to Neo4j: {e}")
            raise
    return driver

@contextmanager
def get_neo4j_session():
    """Yields a Neo4j session using the singleton driver."""
    drv = get_driver()
    session = drv.session()
    try:
        yield session
    finally:
        session.close()

def close_driver():
    global driver
    if driver is not None:
        driver.close()
        driver = None
        logger.info("Neo4j driver closed.")
