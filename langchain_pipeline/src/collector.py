import os
import logging
import json
import csv
from pathlib import Path

# --- Đường dẫn chính ---
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "collector.log"
STATE_FILE = LOG_DIR / "replay_offset.txt"

# Đường dẫn file CSV F5 ASM (đã copy vào project)
CSV_FILE = Path("/home/imsupershy/monitoring-project/f5_logs/f5_asm_logs.csv")

# Số dòng sẽ giả lập mỗi lần chạy (tạm set = 30 dòng ~ tương đương 1 log/2s nếu chạy mỗi phút)
LINES_PER_RUN = 30

# --- Cấu hình logging ---
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [collector] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("collector")


def get_last_offset() -> int:
    """Đọc offset lần trước (đã xử lý đến dòng thứ mấy trong CSV)."""
    if not STATE_FILE.exists():
        return 0
    try:
        return int(STATE_FILE.read_text().strip())
    except Exception:
        return 0


def save_offset(offset: int):
    """Lưu lại offset mới sau khi xử lý."""
    STATE_FILE.write_text(str(offset))


def trim_log(max_size_bytes: int = 2 * 1024 * 1024):
    """
    Cắt bớt file collector.log nếu vượt quá max_size_bytes.
    Giữ lại ~20% cuối file để không mất log mới nhất.
    """
    if not LOG_FILE.exists():
        return

    size = LOG_FILE.stat().st_size
    if size <= max_size_bytes:
        return

    logger.warning("collector.log quá lớn, tiến hành trim...")

    with open(LOG_FILE, "rb") as f:
        data = f.read()

    keep_bytes = int(max_size_bytes * 0.2)
    trimmed = data[-keep_bytes:]

    with open(LOG_FILE, "wb") as f:
        f.write(trimmed)

    logger.info("Trim collector.log hoàn tất (giữ lại 20% cuối).")


def replay_from_csv():
    """
    Đọc một số dòng từ CSV F5 ASM và ghi vào collector.log.
    Mỗi lần chạy chỉ đọc thêm LINES_PER_RUN dòng.
    """
    if not CSV_FILE.exists():
        logger.error(f"File CSV không tồn tại: {CSV_FILE}")
        return

    last_offset = get_last_offset()
    logger.info(f"Bắt đầu replay CSV từ dòng index = {last_offset}")

    processed = 0
    new_offset = last_offset

    with open(CSV_FILE, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        for idx, row in enumerate(reader):
            # Bỏ qua các dòng đã xử lý trước đó
            if idx < last_offset:
                continue

            # Chuẩn hoá dữ liệu: bỏ các key rỗng
            clean_row = {k: v for k, v in row.items() if v not in (None, "", "NaN", "nan")}

            # Chọn một số trường quan trọng để log (cho gọn)
            event = {
                "event_time": clean_row.get("Event Time"),
                "severity": clean_row.get("deviceSeverity"),
                "action": clean_row.get("deviceAction"),
                "event_class": clean_row.get("deviceEventClassId"),
                "name": clean_row.get("name"),
                "source_ip": clean_row.get("sourceAddress"),
                "source_port": clean_row.get("sourcePort"),
                "dest_ip": clean_row.get("destinationAddress"),
                "dest_port": clean_row.get("destinationPort"),
                "request_url": clean_row.get("requestUrl"),
                "request_method": clean_row.get("requestMethod"),
                "application_protocol": clean_row.get("applicationProtocol"),
                "device": clean_row.get("Device"),
                "device_product": clean_row.get("deviceProduct"),
                "device_vendor": clean_row.get("deviceVendor"),
            }

            # Ghi log dưới dạng JSON cho đẹp
            logger.info("[F5-ASM] %s", json.dumps(event, ensure_ascii=False))

            processed += 1
            new_offset = idx + 1

            if processed >= LINES_PER_RUN:
                break

    save_offset(new_offset)
    logger.info(f"Replay xong {processed} dòng, offset mới = {new_offset}")


def main():
    logger.info("Collector (F5 ASM CSV replay) chạy...")
    replay_from_csv()
    trim_log()
    logger.info("Collector kết thúc lượt chạy.")


if __name__ == "__main__":
    main()
