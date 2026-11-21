import pathlib
import subprocess
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "ccdc_wazuh/assets/install-agent.sh"


class AgentScriptTest(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["sh", "-n", str(SCRIPT)], check=True)

    def test_editor_preserves_other_settings_and_updates_server(self):
        script = SCRIPT.read_text().split("# BEGIN CONFIG EDITOR\n", 1)[1].split("# END CONFIG EDITOR", 1)[0]
        source = "<ossec_config>\n  <client>\n    <server>\n      <address>old</address>\n      <port>1514</port>\n      <protocol>tcp</protocol>\n    </server>\n  </client>\n</ossec_config>\n"
        result = subprocess.run(["awk", "-v", "address=manager.example", "-v", "port=1515", script], input=source, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, source.replace("old", "manager.example").replace("1514", "1515"))

    def test_editor_refuses_multiple_servers(self):
        script = SCRIPT.read_text().split("# BEGIN CONFIG EDITOR\n", 1)[1].split("# END CONFIG EDITOR", 1)[0]
        source = "<client>\n<server>\n<address>a</address>\n<port>1514</port>\n</server>\n<server>\n<address>b</address>\n<port>1514</port>\n</server>\n</client>\n"
        result = subprocess.run(["awk", "-v", "address=m", "-v", "port=1514", script], input=source, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
