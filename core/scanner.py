try:
    import winreg
except ModuleNotFoundError:
    winreg = None

class SystemScanner:
    def __init__(self):
        self.run_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        if winreg is None:
            self.hives = []
        else:
            self.hives = [
                (winreg.HKEY_CURRENT_USER, "HKCU"),
                (winreg.HKEY_LOCAL_MACHINE, "HKLM")
            ]

    def check_persistence(self):
        """Détecte les programmes au démarrage"""
        found_items = []
        for hive_id, hive_name in self.hives:
            try:
                key = winreg.OpenKey(hive_id, self.run_path)
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    found_items.append({"name": name, "path": value, "hive": hive_name})
                winreg.CloseKey(key)
            except Exception:
                continue
        return found_items