import json
import re
from loguru import logger
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from Database import WiFiDB

logger.info("Контроллер инициализирован")


@dataclass
class WiFiNetwork:
    bssid: str
    frequency: int
    rssi: int
    ssid: str
    timestamp: int
    channel_bandwidth: str
    capabilities: str


class Controller:
    """Контроллер принимает JSON (строка или байты), парсит в dict,
    создаёт WiFiNetwork и предоставляет методы для сохранения/чтения
    через WiFiDB."""

    def __init__(self, db: Optional[WiFiDB] = None):
        if hasattr(self, '_initialized'):
            return  # Предотвращаем повторную инициализацию
        self._initialized = True
        self.db = db or WiFiDB()
        self.data_processor = None
        self.data = None
        logger.info("Контроллер Controller создан")

    def parse_json(self, payload: Any) -> List[Dict[str, Any]]:
        """Парсит JSON (str/bytes/dict/list) в список dict. Вызывает ValueError
        при некорректном вводе. Если JSON — массив, возвращает список; иначе — одиночный dict в списке."""

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            return [payload]
        try:
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')
            parsed = json.loads(payload)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except Exception as e:
            logger.error(f"Ошибка парсинга JSON: {e}")
            # Fallback на regex, если json.loads сбоит
            return self._extract_with_regex(str(payload))

    def _extract_with_regex(self, json_str: str) -> List[Dict[str, Any]]:
        """Fallback: использует regex для извлечения данных из JSON-строки.
        Ищет все ключ-значение пары для полей WiFiNetwork."""
        logger.warning("Используем regex для извлечения данных из JSON")
        networks = []
        data_dict = {}

        pattern = r'"(\w+)"\s*:\s*["\']?([^"\']+)["\']?\s*,?'
        matches = re.findall(pattern, json_str, re.IGNORECASE)

        for key, value in matches:
            key = key.lower()
            try:
                if key in ['frequency', 'rssi', 'timestamp']:
                    value = int(value)
                data_dict[key] = value
            except ValueError:
                logger.warning(f"Некорректное значение для {key}: {value}")

        # Проверяем наличие всех полей
        required_fields = ['bssid', 'frequency', 'rssi', 'ssid', 'timestamp',
                           'channel_bandwidth', 'capabilities']
        missing = set(required_fields) - set(data_dict.keys())
        if missing:
            logger.error(f"Отсутствуют поля: {missing}")
            raise ValueError("Некорректные данные: отсутствуют обязательные поля")
        else:
            networks.append(data_dict)
            logger.info(f"Извлечено {len(networks)} сеть с regex")

        return networks

    def build_network(self, data: Dict[str, Any]) -> Optional[WiFiNetwork]:
        """Конвертирует dict в WiFiNetwork. Логирует ошибки, но не вызывает raise,
        чтобы не прерывать цикл обработки. Возвращает None при ошибке."""

        logger.debug(f"Строим WiFiNetwork из данных: {data}")
        errors = []

        try:
            frequency = int(data['frequency'])
            if frequency <= 0:
                errors.append("Frequency должна быть положительным числом")
        except (ValueError, KeyError) as e:
            errors.append(f"Некорректное значение frequency: {e}")

        try:
            rssi = int(data['rssi'])
        except (ValueError, KeyError) as e:
            errors.append(f"Некорректное значение rssi: {e}")

        try:
            timestamp = int(data['timestamp'])
            if timestamp <= 0:
                errors.append("Timestamp должен быть положительным числом")
        except (ValueError, KeyError) as e:
            errors.append(f"Некорректное значение timestamp: {e}")

        try:
            bssid = data['bssid']
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                errors.append(f"Некорректный BSSID: {bssid}")
        except KeyError as e:
            errors.append(f"Отсутствует BSSID: {e}")

        if errors:
            ssid = data.get('ssid', 'unknown')
            logger.error(f"Ошибки валидации для сети {ssid}: {', '.join(errors)}")
            return None

        return WiFiNetwork(
            bssid=bssid,
            frequency=frequency,
            rssi=rssi,
            ssid=str(data['ssid']),
            timestamp=timestamp,
            channel_bandwidth=str(data['channel_bandwidth']),
            capabilities=str(data['capabilities']),
        )

    def save_network(self, network: WiFiNetwork) -> bool:
        """Сохраняет WiFiNetwork в БД через WiFiDB.create()."""
        data = {
            'bssid': network.bssid,
            'frequency': network.frequency,
            'rssi': network.rssi,
            'ssid': network.ssid,
            'timestamp': network.timestamp,
            'channel_bandwidth': network.channel_bandwidth,
            'capabilities': network.capabilities,
        }
        logger.info(f"Сохраняем сеть: {network.ssid} ({network.bssid})")
        result = self.db.create(data)
        if result:
            logger.info("Сеть успешно сохранена в БД")
        else:
            logger.error("Ошибка сохранения сети в БД")
        return result

    def process_payload_and_save(self, payload: Any) -> bool:
        """Удобный метод: парсит payload, строит модель и сохраняет.
        Возвращает True при успехе."""
        logger.info("Начинаем обработку payload")
        networks_data = self.parse_json(payload)
        success_count = 0
        error_count = 0
        errors = []  # Собираем ошибки для финального лога
        for net_data in networks_data:
            network = self.build_network(net_data)
            if network is None:
                error_count += 1
                continue
            if self.save_network(network):
                success_count += 1
            else:
                error_count += 1
                errors.append(f"Ошибка сохранения для {net_data.get('ssid', 'unknown')}")
        if errors:
            logger.error(f"Сводка ошибок: {', '.join(errors)}")
        logger.info(f"Обработано {success_count} успешно, "
                    f"{error_count} с ошибками из {len(networks_data)} сетей")
        return success_count > 0

    def logic(self):
        """Логика контроллера: инициализация БД и проверка."""
        logger.debug("Дополнительная логика вызвана")
        # Убрал тест, чтобы избежать повторных вызовов __init__
        # Если нужно, добавьте условную логику здесь
        pass
