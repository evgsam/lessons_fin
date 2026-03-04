import os
import pandas as pd


def read_suricata_logs() -> pd.DataFrame:
    """Читает Suricata eve.json из src/suricata_logs/honeypot-2018/."""
    current_dir = os.path.dirname(os.path.abspath(__file__))  # /.../lessons_fin/src
    project_root = os.path.dirname(current_dir)                # /.../lessons_fin
    log_path = os.path.join(project_root, "suricata_logs", "honeypot-2018", "eve.json")
    print(f"Читаем логи: {log_path}")
  
    # Проверяем существование файла
    if not os.path.exists(log_path):
        return None
    
    # Читаем JSON
    logs_df = pd.read_json(log_path, lines=True)
    print(f"Загружено событий: {len(logs_df)}")
    return logs_df
