import uuid
import random
from datetime import datetime, timezone


# --------------------------------------------------
# EV CHARGER SIMULATOR
# --------------------------------------------------

class EVCharger:

    def __init__(
        self,
        charger_id,
        location="Unknown",
        connector_count=1,
        protocol="OCPP 1.6"
    ):
        self.charger_id = charger_id
        self.location = location
        self.connector_count = connector_count
        self.protocol = protocol

        self.status = "Available"
        self.energy_kwh = 0.0
        self.transaction_id = None

        self.message_history = []

    # --------------------------------------------------
    # MESSAGE CREATION
    # --------------------------------------------------

    def create_message(self, message_type, payload=None):
        """
        Creates a simulated OCPP-style message.

        Every message receives a unique message ID and
        timestamp to distinguish new messages from replays.
        """

        message = {
            "message_id": str(uuid.uuid4()),
            "charger_id": self.charger_id,
            "message_type": message_type,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "payload": payload or {}
        }

        self.message_history.append(message)

        return message

    # --------------------------------------------------
    # BOOT NOTIFICATION
    # --------------------------------------------------

    def boot_notification(self):
        """
        Simulates a charger BootNotification message.
        """

        payload = {
            "charge_point_vendor": "EVSecure",
            "charge_point_model": "EVS-M3",
            "firmware_version": "1.0.0"
        }

        return self.create_message(
            "BootNotification",
            payload
        )

    # --------------------------------------------------
    # HEARTBEAT
    # --------------------------------------------------

    def heartbeat(self):
        """
        Simulates a periodic Heartbeat message.
        """

        payload = {
            "status": self.status,
            "heartbeat_interval": 60
        }

        return self.create_message(
            "Heartbeat",
            payload
        )

    # --------------------------------------------------
    # STATUS NOTIFICATION
    # --------------------------------------------------

    def status_notification(self, status=None):
        """
        Simulates a StatusNotification message.
        """

        if status:
            self.status = status

        payload = {
            "connector_id": 1,
            "status": self.status,
            "error_code": "NoError"
        }

        return self.create_message(
            "StatusNotification",
            payload
        )

    # --------------------------------------------------
    # START TRANSACTION
    # --------------------------------------------------

    def start_transaction(self, id_tag="USER-001"):
        """
        Simulates the start of a charging transaction.
        """

        if self.status == "Charging":
            raise ValueError(
                "A transaction is already active."
            )

        self.transaction_id = str(
            uuid.uuid4()
        )

        self.energy_kwh = 0.0
        self.status = "Charging"

        payload = {
            "transaction_id": self.transaction_id,
            "connector_id": 1,
            "id_tag": id_tag,
            "meter_start": 0,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()
        }

        return self.create_message(
            "StartTransaction",
            payload
        )

    # --------------------------------------------------
    # ENERGY UPDATE
    # --------------------------------------------------

    def update_energy(self, energy_kwh=None):
        """
        Updates the simulated energy consumption.
        """

        if self.status != "Charging":
            raise ValueError(
                "Cannot update energy when charger is not charging."
            )

        if energy_kwh is None:
            energy_kwh = round(
                random.uniform(0.1, 2.0),
                2
            )

        if energy_kwh < 0:
            raise ValueError(
                "Energy consumption cannot be negative."
            )

        self.energy_kwh += float(energy_kwh)

        return self.energy_kwh

    # --------------------------------------------------
    # METER VALUES
    # --------------------------------------------------

    def meter_values(self):
        """
        Simulates a MeterValues message.
        """

        if self.status != "Charging":
            raise ValueError(
                "Charger is not currently charging."
            )

        payload = {
            "connector_id": 1,
            "transaction_id": self.transaction_id,
            "energy_kwh": round(self.energy_kwh, 3),
            "power_kw": round(
                random.uniform(3.0, 7.0),
                2
            ),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()
        }

        return self.create_message(
            "MeterValues",
            payload
        )

    # --------------------------------------------------
    # STOP TRANSACTION
    # --------------------------------------------------

    def stop_transaction(self):
        """
        Simulates the end of a charging transaction.
        """

        if self.status != "Charging":
            raise ValueError(
                "No active transaction to stop."
            )

        payload = {
            "transaction_id": self.transaction_id,
            "meter_stop": round(
                self.energy_kwh * 1000,
                2
            ),
            "energy_kwh": round(
                self.energy_kwh,
                3
            ),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "reason": "Local"
        }

        message = self.create_message(
            "StopTransaction",
            payload
        )

        self.status = "Available"
        self.transaction_id = None

        return message

    # --------------------------------------------------
    # DISCONNECT
    # --------------------------------------------------

    def disconnect(self):
        """
        Simulates charger disconnection.
        """

        self.status = "Unavailable"

        return self.status

    # --------------------------------------------------
    # RECONNECT
    # --------------------------------------------------

    def reconnect(self):
        """
        Simulates charger reconnection.
        """

        if self.transaction_id:
            self.status = "Charging"
        else:
            self.status = "Available"

        return self.status

    # --------------------------------------------------
    # CHARGER INFORMATION
    # --------------------------------------------------

    def get_status(self):
        """
        Returns the current charger state.
        """

        return {
            "charger_id": self.charger_id,
            "location": self.location,
            "connector_count": self.connector_count,
            "protocol": self.protocol,
            "status": self.status,
            "energy_kwh": round(
                self.energy_kwh,
                3
            ),
            "transaction_id": self.transaction_id
        }

    # --------------------------------------------------
    # MESSAGE HISTORY
    # --------------------------------------------------

    def get_message_history(self):
        return self.message_history


# --------------------------------------------------
# QUICK SIMULATION TEST
# --------------------------------------------------

if __name__ == "__main__":

    charger = EVCharger(
        charger_id="EV-001",
        location="Delhi",
        connector_count=2
    )

    print("\nEVSECURE-MIGRATE")
    print("EV CHARGER SIMULATOR")
    print("-" * 45)

    print("\n1. Boot Notification")
    print(charger.boot_notification())

    print("\n2. Heartbeat")
    print(charger.heartbeat())

    print("\n3. Start Transaction")
    print(charger.start_transaction())

    print("\n4. Update Energy")
    charger.update_energy(2.5)
    print("Energy:", charger.energy_kwh, "kWh")

    print("\n5. Meter Values")
    print(charger.meter_values())

    print("\n6. Stop Transaction")
    print(charger.stop_transaction())

    print("\n7. Final Charger Status")
    print(charger.get_status())

    print("\nSimulation completed.")