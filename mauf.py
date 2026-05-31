import psycopg2

# PostgreSQL Connection
conn = psycopg2.connect(
    host="localhost",
    port=5432,
    database="ai_network_watcher",
    user="mangesh",
    password="Admin"
)

cur = conn.cursor()

#file_path = "C:\Users\admin\Downloads\manuf\manuf"
file_path = r"C:\Users\admin\Downloads\manuf\manuf"

with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

    for line in f:

        # Skip comments
        if line.startswith("#") or not line.strip():
            continue

        parts = line.strip().split()

        if len(parts) < 3:
            continue

        mac_prefix = parts[0]
        vendor_short = parts[1]

        # Remaining columns become full vendor name
        vendor_full = " ".join(parts[2:])

        cur.execute(
            """
            INSERT INTO mac_vendors
            (
                mac_prefix,
                vendor_short_name,
                vendor_full_name
            )
            VALUES (%s,%s,%s)
            """,
            (
                mac_prefix,
                vendor_short,
                vendor_full
            )
        )

conn.commit()

cur.close()
conn.close()

print("✅ MAC Vendor Data Loaded Successfully")