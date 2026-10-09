import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class MeasurementTest(unittest.TestCase):
    def test_cpp_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="measurement-test-") as tmp:
            binary = pathlib.Path(tmp) / "probe"
            subprocess.run([
                "g++", "-std=c++17", "-O2", "-pthread", "-I", str(ROOT / "My-YCSB/core/include"),
                str(ROOT / "scripts/tests/measurement_boundaries.cc"),
                *[str(ROOT / f"My-YCSB/core/{name}.cpp")
                  for name in ("measurement", "worker", "workload", "client")],
                "-o", str(binary),
            ], check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
