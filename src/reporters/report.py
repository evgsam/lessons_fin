import os
import pandas as pd
import matplotlib.pyplot as plt

def save_report(threats):
    """Сохраняет отчёт в CSV и строит график топ-5 IP."""
    # Создаём папку reports/
    current_dir = os.path.dirname(os.path.abspath(__file__))  # /.../src
    project_root = os.path.dirname(current_dir)               # /.../lessons_fin
    reports_dir = os.path.join(project_root, "reports")
    
    os.makedirs(reports_dir, exist_ok=True)
    print(f"Создан reports: {reports_dir}")
    
    # Сохраняем CSV
    df_threats = pd.DataFrame(threats)
    csv_path = os.path.join(reports_dir, "threats.csv")
    df_threats.to_csv(csv_path, index=False)
    print(f"Отчёт: {csv_path}")
    
    # График ТОП-5 IP
    ip_threats = [t for t in threats if t['type'] == 'SUSPICIOUS_IP']
    if ip_threats:
        ips = [t['ip'] for t in ip_threats]
        counts = [t['alerts_count'] for t in ip_threats]
        
        plt.figure(figsize=(10,6))
        plt.bar(ips, counts, color='red', alpha=0.7)
        plt.title('Топ-5 подозрительных IP (по алертам Suricata)')
        plt.xlabel('IP-адрес')
        plt.ylabel('Количество алертов')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        png_path = os.path.join(reports_dir, "top_ips.png")
        plt.savefig(png_path, dpi=300, bbox_inches='tight')
        plt.show()
        print(f"График: {png_path}")
    else:
        print("Нет IP-угроз для графика")

