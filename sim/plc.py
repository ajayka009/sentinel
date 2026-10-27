"""Simulated PLC: pymodbus Modbus/TCP server on localhost:5020.

Holding registers (device id 1):
    HR 0 : run/stop command   (0 = STOP, 1 = RUN)
    HR 1 : speed setpoint      (RPM, 0..3000)

Every write request is logged to stdout.
"""

import argparse
import asyncio
import logging

from pymodbus.simulator import DataType, SimData, SimDevice
from pymodbus.server import ModbusTcpServer

HR_RUN_STOP = 0
HR_SPEED_SETPOINT = 1

SPEED_MAX_RPM = 3000

WRITE_FUNCTION_CODES = {5, 6, 15, 16, 22, 23}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s plc %(levelname)s %(message)s",
)
log = logging.getLogger("plc")


def trace_pdu(sending: bool, pdu):
    """Log every incoming write request (address + value)."""
    if not sending and pdu.function_code in WRITE_FUNCTION_CODES:
        address = getattr(pdu, "address", "?")
        value = getattr(pdu, "registers", None) or getattr(pdu, "bits", "?")
        log.info(
            "WRITE fc=%s address=HR%s value=%s",
            pdu.function_code,
            address,
            value,
        )
    return pdu


async def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated PLC (Modbus/TCP).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    args = parser.parse_args()

    device = SimDevice(
        id=1,
        simdata=[
            SimData(address=HR_RUN_STOP, count=1, values=0, datatype=DataType.REGISTERS),
            SimData(address=HR_SPEED_SETPOINT, count=1, values=0, datatype=DataType.REGISTERS),
        ],
    )
    server = ModbusTcpServer(
        context=[device],
        address=(args.host, args.port),
        trace_pdu=trace_pdu,
    )
    log.info(
        "PLC listening on %s:%s (HR0=run/stop, HR1=speed setpoint)",
        args.host,
        args.port,
    )
    await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
