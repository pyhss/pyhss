# Copyright 2025 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
import time

import sqlalchemy
from sqlalchemy.engine import Engine
from sqlalchemy_utils import create_database, database_exists


class DatabaseSchema:
    latest = 2

    def __init__(self, logTool, base, engine: Engine, main_service: bool):
        self.logTool = logTool
        self.base = base
        self.engine = engine

        if not self.is_ready():
            if main_service:
                self.init_db()
            else:
                self.wait_until_ready()

    def table_exists(self, table):
        inspector = sqlalchemy.inspect(self.engine)
        return table in inspector.get_table_names()

    def column_exists(self, table, column):
        inspector = sqlalchemy.inspect(self.engine)
        columns = inspector.get_columns(table)

        for col in columns:
            if col["name"] == column:
                return True

        return False

    def get_version(self):
        ret = 0
        if not self.table_exists("database_schema_version"):
            return ret
        try:
            sql = """
                SELECT upgrade_id
                FROM database_schema_version
                ORDER BY upgrade_id DESC
                LIMIT 1
            """
            with self.engine.connect() as conn:
                result = conn.execute(sqlalchemy.text(sql)).fetchone()
                if result:
                    ret = result[0]
        except Exception:  # noqa: S110 - ignoring is fine; callers log on failure
            pass
        return ret

    def execute(self, sql):
        with self.engine.connect() as conn:
            conn.execute(sqlalchemy.text(sql))
            conn.commit()

    def set_version(self, new_version):
        self.logTool.log(
            service="Database",
            level="info",
            message=f"New database schema version is {new_version}",
        )
        self.execute(f"""
            INSERT INTO database_schema_version (upgrade_id, comment)
            VALUES ({int(new_version)}, 'automatic upgrade from PyHSS')
        """)

    def is_ready(self):
        if not database_exists(self.engine.url):
            return False
        return self.get_version() == self.latest

    def wait_until_ready(self):
        self.logTool.log(
            service="Database",
            level="info",
            message="Waiting for the main service to prepare the database",
        )

        for i in range(100):
            time.sleep(0.2)
            if self.is_ready():
                return

        self.logTool.log(
            service="Database",
            level="error",
            message="Database did not get ready. Is pyhss_hss (hssService) running?",
        )
        sys.exit(10)

    def ensure_release_1_0_1_or_newer(self):
        expected = {
            "apn": [
                "nbiot",
                "nidd_scef_id",
                "nidd_scef_realm",
                "nidd_mechanism",
                "nidd_rds",
                "nidd_preferred_data_mode",
            ],
            "ims_subscriber": [
                "xcap_profile",
                "sh_template_path",
            ],
            "operation_log": [
                "roaming_rule_id",
                "roaming_network_id",
                "emergency_subscriber_id",
            ],
            "subscriber": [
                "roaming_enabled",
                "roaming_rule_list",
            ],
        }

        for table, columns in expected.items():
            for column in columns:
                if not self.column_exists(table, column):
                    self.logTool.log(
                        service="Database",
                        level="warning",
                        message=f"Database column missing: {table}.{column}",
                    )
                    self.logTool.log(
                        service="Database",
                        level="error",
                        message="Database schemas from before PyHSS 1.0.1 are not supported."
                        " Start with a new database or migrate manually:"
                        " https://github.com/nickvsnetworking/pyhss/blob/master/CHANGELOG.md#101---2024-01-23",
                    )
                    sys.exit(20)

    def init_db(self):
        # Create database if it does not exist
        if not database_exists(self.engine.url):
            self.logTool.log(
                service="Database",
                level="debug",
                message="Creating database",
            )
            create_database(self.engine.url)

        if not self.table_exists("subscriber"):
            # Assume completely empty database (either because it was just
            # created, or for mysql/postgresql an admin may create the database
            # first before an application accesses it with a different user)
            self.logTool.log(
                service="Database",
                level="debug",
                message="Initializing empty database",
            )
            self.base.metadata.create_all(self.engine)
            self.set_version(self.latest)
        else:
            version = self.get_version()
            self.logTool.log(
                service="Database",
                level="debug",
                message=f"Database already created (schema version: {version})",
            )
            if version > self.latest:
                self.logTool.log(
                    service="Database",
                    level="warning",
                    message=f"Database schema version {version} is higher than latest known version {self.latest}",
                )
            if version < self.latest:
                self.ensure_release_1_0_1_or_newer()
                self.upgrade_all()

    def upgrade_msg(self, new_version):
        self.logTool.log(
            service="Database",
            level="info",
            message=f"Upgrading database schema to version {new_version}",
        )

    def add_column(self, table, column, typename):
        if self.column_exists(table, column):
            return
        if typename == "DATETIME" and self.engine.name == "postgresql":
            # PostgreSQL doesn't have DATETIME:
            # https://www.postgresql.org/docs/current/datatype-datetime.html
            typename = "TIMESTAMP"

        self.execute(f"ALTER TABLE {table} ADD {column} {typename}")

    def upgrade_from_20240603_release_1_0_1(self):
        if self.get_version() >= 1:
            return
        self.upgrade_msg(1)
        self.base.metadata.tables["database_schema_version"].create(bind=self.engine)
        self.add_column("auc", "algo", "VARCHAR(20)")
        self.add_column("subscriber", "last_location_update_timestamp", "DATETIME")
        self.add_column("subscriber", "last_seen_cell_id", "VARCHAR(64)")
        self.add_column("subscriber", "last_seen_eci", "VARCHAR(64)")
        self.add_column("subscriber", "last_seen_enodeb_id", "VARCHAR(64)")
        self.add_column("subscriber", "last_seen_mcc", "VARCHAR(3)")
        self.add_column("subscriber", "last_seen_mnc", "VARCHAR(3)")
        self.add_column("subscriber", "last_seen_tac", "VARCHAR(64)")
        self.add_column("subscriber", "serving_msc", "VARCHAR(512)")
        self.add_column("subscriber", "serving_msc_timestamp", "DATETIME")
        self.add_column("subscriber", "serving_sgsn", "VARCHAR(512)")
        self.add_column("subscriber", "serving_sgsn_timestamp", "DATETIME")
        self.add_column("subscriber", "serving_vlr", "VARCHAR(512)")
        self.add_column("subscriber", "serving_vlr_timestamp", "DATETIME")
        self.set_version(1)

    def upgrade_to_v2(self):
        if self.get_version() >= 2:
            return
        self.upgrade_msg(2)
        self.add_column("apn", "sst", "INTEGER")
        self.add_column("apn", "sd", "VARCHAR(6)")
        self.add_column("subscriber", "serving_amf", "VARCHAR(512)")
        self.add_column("subscriber", "serving_amf_timestamp", "DATETIME")
        self.set_version(2)

    def upgrade_all(self):
        self.upgrade_from_20240603_release_1_0_1()
        self.upgrade_to_v2()
