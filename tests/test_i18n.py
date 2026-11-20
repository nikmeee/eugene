import os
import unittest
from unittest.mock import patch

from eugene.doctor import Doctor
from eugene.i18n import detect_language, tr_error, use


class LanguageTests(unittest.TestCase):
    def tearDown(self):
        use("en")

    def test_system_russian_wins_over_the_terminal(self):
        with patch("eugene.i18n.sys.platform", "darwin"), \
                patch("eugene.i18n.subprocess.run") as run, \
                patch.dict(os.environ, {"LANG": "C.UTF-8"}):
            run.return_value.stdout = '(\n    "ru-RU",\n    "en-US"\n)\n'
            self.assertEqual(detect_language(), "ru")

    def test_system_english_is_not_overruled_by_lang(self):
        with patch("eugene.i18n.sys.platform", "darwin"), \
                patch("eugene.i18n.subprocess.run") as run, \
                patch.dict(os.environ, {"LANG": "ru_RU.UTF-8"}):
            run.return_value.stdout = '(\n    "en-US"\n)\n'
            self.assertEqual(detect_language(), "en")

    def test_posix_locale_is_the_fallback(self):
        with patch("eugene.i18n.sys.platform", "linux"), \
                patch.dict(os.environ, {"LC_ALL": "", "LC_MESSAGES": "", "LANG": "ru_RU.UTF-8"}):
            self.assertEqual(detect_language(), "ru")

    def test_report_follows_the_selected_language(self):
        use("ru")
        doc = Doctor()
        doc.finish()
        self.assertEqual(doc.report.nodes["link"]["label"], "Сеть")
        self.assertEqual(doc.report.headline, "Сеть здорова, как краб в отпуске!")

    def test_known_probe_errors_are_translated_and_unknown_ones_pass_through(self):
        use("ru")
        self.assertEqual(tr_error("TCP timeout"), "таймаут TCP")
        self.assertEqual(tr_error("DNS returned a spoofed address 10.0.0.1"), "DNS вернул подменный адрес 10.0.0.1")
        self.assertEqual(tr_error("Connection reset by peer"), "Connection reset by peer")


if __name__ == "__main__":
    unittest.main()
