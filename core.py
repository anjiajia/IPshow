from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import pickle
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from babel import Locale
except ImportError:
    Locale = None


IPIP_QUERY_URL = "https://ipapi.ipip.net/v2/query/"
IPIP_RISK_URL = "https://ipapi.ipip.net/v2/risk/portrait/"
IP_API_BATCH_URL = "http://ip-api.com/batch"
ABUSE_IPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
IP_API_FIELDS = ",".join(
    [
        "status",
        "message",
        "query",
        "country",
        "countryCode",
        "regionName",
        "city",
        "district",
        "zip",
        "lat",
        "lon",
        "timezone",
        "isp",
        "org",
        "as",
        "mobile",
        "proxy",
        "hosting",
    ]
)
MAX_BATCH_SIZE = 100
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0 Safari/537.36"
    ),
    "Accept": "application/json",
}
SUPPORTED_PROVIDERS = {
    "auto": "自动（优先 IPIP，失败时回退免费接口）",
    "ipip": "IPIP（推荐，中国可用，中文结果）",
    "ip_sb": "IP.SB（HTTPS，英文结果为主）",
    "ip_api": "ip-api（免费版，仅 HTTP）",
}
ABUSE_CONFIDENCE_LEVELS = [
    (75, "高风险"),
    (25, "中风险"),
    (1, "低风险"),
    (0, "未发现风险"),
]

CACHE_DIR = ".ipshow_cache"
CACHE_TTL_SECONDS = 3600

IPIP_DELAY = 0.5
IP_SB_DELAY = 1.2
ABUSE_DELAY = 1.2
IP_API_CHUNK_DELAY = 1.5

CONFIG_FILE = ".ipshow_config.json"
HISTORY_DIR = ".ipshow_history"
MAX_HISTORY_ITEMS = 50
MAX_CIDR_EXPAND = 1024


@dataclass
class ParseResult:
    ips: list[str]
    invalid_values: list[str]


@dataclass
class AppConfig:
    ipip_token: str = ""
    provider: str = "auto"
    ipip_risk_token: str = ""
    abuse_api_key: str = ""

    @classmethod
    def load(cls) -> AppConfig:
        if not os.path.exists(CONFIG_FILE):
            return cls()
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls(
                ipip_token=data.get("ipip_token", ""),
                provider=data.get("provider", "auto"),
                ipip_risk_token=data.get("ipip_risk_token", ""),
                abuse_api_key=data.get("abuse_api_key", ""),
            )
        except Exception:
            return cls()

    def save(self) -> None:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "ipip_token": self.ipip_token,
                        "provider": self.provider,
                        "ipip_risk_token": self.ipip_risk_token,
                        "abuse_api_key": self.abuse_api_key,
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        except Exception:
            pass


def normalize_lines(raw_text: str) -> list[str]:
    return [
        item.strip()
        for line in raw_text.splitlines()
        for item in line.replace("，", ",").replace(";", ",").split(",")
        if item.strip()
    ]


def expand_cidr(value: str) -> list[str]:
    try:
        network = ipaddress.ip_network(value, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > MAX_CIDR_EXPAND:
            return [str(ip) for ip in hosts[:MAX_CIDR_EXPAND]]
        return [str(ip) for ip in hosts]
    except ValueError:
        return []


def validate_ip_list(values: Iterable[str]) -> ParseResult:
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()

    for value in values:
        # Try as single IP first
        try:
            ip = str(ipaddress.ip_address(value))
            if ip not in seen:
                seen.add(ip)
                valid.append(ip)
            continue
        except ValueError:
            pass

        # Try as CIDR
        expanded = expand_cidr(value)
        if expanded:
            for ip in expanded:
                if ip not in seen:
                    seen.add(ip)
                    valid.append(ip)
            continue

        invalid.append(value)

    return ParseResult(ips=valid, invalid_values=invalid)


def create_retry_session(
    retries: int = 3,
    backoff_factor: float = 1,
    status_forcelist: tuple[int, ...] = (429, 500, 502, 503, 504),
) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=None,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    return session


def _get_cache_key(provider: str, ip_list: list[str], extra: str = "") -> str:
    content = json.dumps({"p": provider, "ips": sorted(ip_list), "e": extra}, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()


def _save_cache(key: str, df: pd.DataFrame) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{key}.pkl")
    with open(path, "wb") as f:
        pickle.dump(df, f)


def _load_cache(key: str) -> pd.DataFrame | None:
    path = os.path.join(CACHE_DIR, f"{key}.pkl")
    if not os.path.exists(path):
        return None
    if time.time() - os.path.getmtime(path) > CACHE_TTL_SECONDS:
        os.remove(path)
        return None
    with open(path, "rb") as f:
        return pickle.load(f)


def _has_successful_lookup(df: pd.DataFrame) -> bool:
    if df.empty or "查询状态" not in df.columns:
        return False
    return df["查询状态"].eq("success").any()


def _summarize_lookup_failure(provider_label: str, df: pd.DataFrame) -> str:
    if df.empty:
        return f"{provider_label} 未返回结果"
    if "错误信息" not in df.columns:
        return f"{provider_label} 未返回成功结果"

    messages = [str(value) for value in df["错误信息"].dropna().unique().tolist() if str(value)]
    if not messages:
        return f"{provider_label} 未返回成功结果"
    return f"{provider_label} 失败：{'；'.join(messages[:3])}"


def extract_ips_from_upload(uploaded_file) -> list[str]:
    suffix = uploaded_file.name.rsplit(".", 1)[-1].lower()

    if suffix == "txt":
        content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
        return normalize_lines(content)

    if suffix == "csv":
        df = pd.read_csv(uploaded_file, dtype=str)
    elif suffix in {"xls", "xlsx"}:
        df = pd.read_excel(uploaded_file, dtype=str)
    else:
        raise ValueError("仅支持 TXT、CSV、XLS、XLSX 文件")

    flat_values = (
        value.strip()
        for value in df.fillna("").astype(str).to_numpy().flatten().tolist()
        if value and value.strip()
    )
    return list(flat_values)


def batched(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _concurrent_batch_lookup(
    ip_list: list[str],
    lookup_single: Callable[[str], dict],
    max_workers: int,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    results: list[dict] = [{}] * len(ip_list)
    total = len(ip_list)
    if total == 0:
        return pd.DataFrame()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(lookup_single, ip): i for i, ip in enumerate(ip_list)}
        for i, future in enumerate(as_completed(future_map), start=1):
            results[future_map[future]] = future.result()
            if progress_callback is not None:
                progress_callback(i, total)

    return pd.DataFrame(results)


def get_country_name_zh(country_code: str, fallback: str = "") -> str:
    if not country_code:
        return fallback
    if Locale is None:
        return fallback
    try:
        return Locale.parse("zh_Hans").territories.get(country_code.upper(), fallback) or fallback
    except Exception:
        return fallback


def lookup_ip_api_batch(
    ip_list: list[str],
    timeout: int = 15,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    rows: list[dict] = []
    session = create_retry_session()

    for chunk_index, chunk in enumerate(batched(ip_list, MAX_BATCH_SIZE), start=1):
        payload = [{"query": ip, "fields": IP_API_FIELDS} for ip in chunk]
        try:
            response = session.post(IP_API_BATCH_URL, json=payload, timeout=timeout)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            for ip in chunk:
                rows.append(
                    {
                        "IP": ip,
                        "查询状态": "fail",
                        "错误信息": f"批次请求失败: {exc}",
                        "国家": "",
                        "国家英文": "",
                        "省/州": "",
                        "城市": "",
                        "区县": "",
                        "邮编": "",
                        "时区": "",
                        "纬度": "",
                        "经度": "",
                        "运营商": "",
                        "组织": "",
                        "自治系统": "",
                        "移动网络": "否",
                        "代理": "否",
                        "托管机房": "否",
                    }
                )
            if progress_callback is not None:
                progress_callback(min(chunk_index * MAX_BATCH_SIZE, len(ip_list)), len(ip_list))
            time.sleep(IP_API_CHUNK_DELAY)
            continue

        for item in data:
            rows.append(
                {
                    "IP": item.get("query", ""),
                    "查询状态": item.get("status", ""),
                    "错误信息": item.get("message", ""),
                    "国家": get_country_name_zh(item.get("countryCode", ""), item.get("country", "")),
                    "国家英文": item.get("country", ""),
                    "省/州": item.get("regionName", ""),
                    "城市": item.get("city", ""),
                    "区县": item.get("district", ""),
                    "邮编": item.get("zip", ""),
                    "时区": item.get("timezone", ""),
                    "纬度": item.get("lat", ""),
                    "经度": item.get("lon", ""),
                    "运营商": item.get("isp", ""),
                    "组织": item.get("org", ""),
                    "自治系统": item.get("as", ""),
                    "移动网络": "是" if item.get("mobile") else "否",
                    "代理": "是" if item.get("proxy") else "否",
                    "托管机房": "是" if item.get("hosting") else "否",
                }
            )

        if progress_callback is not None:
            progress_callback(min(chunk_index * MAX_BATCH_SIZE, len(ip_list)), len(ip_list))
        time.sleep(IP_API_CHUNK_DELAY)

    return pd.DataFrame(rows)


def lookup_ipip_batch(
    ip_list: list[str],
    token: str,
    timeout: int = 15,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    def lookup_single(ip: str) -> dict:
        session = create_retry_session()
        try:
            response = session.get(
                f"{IPIP_QUERY_URL}{ip}",
                params={"token": token},
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if payload.get("ret") != "ok":
                raise requests.RequestException(payload.get("msg", "IPIP 查询失败"))

            info = payload.get("data", {}).get("info", {})
            time.sleep(IPIP_DELAY)
            return {
                "IP": payload.get("data", {}).get("ip", ip),
                "查询状态": "success",
                "错误信息": "",
                "国家": info.get("country_name", ""),
                "国家英文": "",
                "省/州": info.get("region_name", ""),
                "城市": info.get("city_name", ""),
                "区县": info.get("district_name", ""),
                "邮编": info.get("postal_code", ""),
                "时区": info.get("timezone", ""),
                "纬度": info.get("latitude", ""),
                "经度": info.get("longitude", ""),
                "运营商": info.get("line", "") or info.get("isp_domain", ""),
                "组织": info.get("owner_domain", ""),
                "自治系统": info.get("asn", ""),
                "移动网络": "是" if info.get("usage_type") == "移动网络" else "否",
                "代理": "",
                "托管机房": "是" if info.get("usage_type") in {"IDC", "数据中心"} else "否",
                "IP类型": info.get("usage_type", ""),
            }
        except Exception as exc:
            time.sleep(IPIP_DELAY)
            return {
                "IP": ip,
                "查询状态": "fail",
                "错误信息": str(exc),
                "国家": "",
                "国家英文": "",
                "省/州": "",
                "城市": "",
                "区县": "",
                "邮编": "",
                "时区": "",
                "纬度": "",
                "经度": "",
                "运营商": "",
                "组织": "",
                "自治系统": "",
                "移动网络": "否",
                "代理": "",
                "托管机房": "否",
                "IP类型": "",
            }

    return _concurrent_batch_lookup(ip_list, lookup_single, max_workers=8, progress_callback=progress_callback)


def _lookup_ip_batch_core(
    ip_list: list[str],
    provider: str,
    ipip_token: str = "",
    timeout: int = 15,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    if provider == "ipip":
        if not ipip_token:
            raise ValueError("使用 IPIP 数据源时需要填写 IPIP Token")
        return lookup_ipip_batch(
            ip_list,
            token=ipip_token,
            timeout=timeout,
            progress_callback=progress_callback,
        )

    if provider == "ip_api":
        return lookup_ip_api_batch(
            ip_list,
            timeout=timeout,
            progress_callback=progress_callback,
        )

    if provider == "ip_sb":
        def lookup_single(ip: str) -> dict:
            session = create_retry_session()
            try:
                response = session.get(f"https://api.ip.sb/geoip/{ip}", timeout=timeout)
                response.raise_for_status()
                item = response.json()
                time.sleep(IP_SB_DELAY)
                return {
                    "IP": item.get("ip", ip),
                    "查询状态": "success" if not item.get("error") else "fail",
                    "错误信息": item.get("error", ""),
                    "国家": get_country_name_zh(item.get("country_code", ""), item.get("country", "")),
                    "国家英文": item.get("country", ""),
                    "省/州": item.get("region", ""),
                    "城市": item.get("city", ""),
                    "区县": "",
                    "邮编": item.get("postal_code", ""),
                    "时区": item.get("timezone", ""),
                    "纬度": item.get("latitude", ""),
                    "经度": item.get("longitude", ""),
                    "运营商": item.get("isp", ""),
                    "组织": item.get("organization", ""),
                    "自治系统": item.get("asn_organization", ""),
                    "移动网络": "",
                    "代理": "",
                    "托管机房": "",
                }
            except Exception as exc:
                time.sleep(IP_SB_DELAY)
                return {
                    "IP": ip,
                    "查询状态": "fail",
                    "错误信息": str(exc),
                    "国家": "",
                    "国家英文": "",
                    "省/州": "",
                    "城市": "",
                    "区县": "",
                    "邮编": "",
                    "时区": "",
                    "纬度": "",
                    "经度": "",
                    "运营商": "",
                    "组织": "",
                    "自治系统": "",
                    "移动网络": "",
                    "代理": "",
                    "托管机房": "",
                }

        return _concurrent_batch_lookup(ip_list, lookup_single, max_workers=6, progress_callback=progress_callback)

    if provider == "auto":
        errors: list[str] = []

        if ipip_token:
            try:
                df = lookup_ip_batch(
                    ip_list,
                    provider="ipip",
                    ipip_token=ipip_token,
                    timeout=timeout,
                    progress_callback=progress_callback,
                )
                if _has_successful_lookup(df):
                    df.attrs["resolved_provider"] = "ipip"
                    return df
                errors.append(_summarize_lookup_failure("IPIP", df))
            except (requests.RequestException, ValueError) as exc:
                errors.append(f"IPIP 失败：{exc}")

        try:
            df = lookup_ip_batch(
                ip_list,
                provider="ip_api",
                ipip_token=ipip_token,
                timeout=timeout,
                progress_callback=progress_callback,
            )
            if _has_successful_lookup(df):
                df.attrs["resolved_provider"] = "ip_api"
                return df
            errors.append(_summarize_lookup_failure("ip-api", df))
        except requests.RequestException as exc:
            errors.append(f"ip-api 失败：{exc}")

        try:
            df = lookup_ip_batch(
                ip_list,
                provider="ip_sb",
                ipip_token=ipip_token,
                timeout=timeout,
                progress_callback=progress_callback,
            )
            if _has_successful_lookup(df):
                df.attrs["resolved_provider"] = "ip_sb"
                return df
            errors.append(_summarize_lookup_failure("IP.SB", df))
        except requests.RequestException as exc:
            errors.append(f"IP.SB 失败：{exc}")

        raise requests.RequestException("；".join(errors))

    raise ValueError(f"不支持的数据源：{provider}")


def lookup_ip_batch(
    ip_list: list[str],
    provider: str,
    ipip_token: str = "",
    timeout: int = 15,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    cache_key = _get_cache_key(provider, ip_list, extra=f"token={bool(ipip_token)}")
    cached_df = _load_cache(cache_key)
    if cached_df is not None and _has_successful_lookup(cached_df):
        cached_df.attrs.setdefault("resolved_provider", provider)
        if progress_callback is not None:
            progress_callback(len(ip_list), len(ip_list))
        return cached_df

    df = _lookup_ip_batch_core(
        ip_list,
        provider=provider,
        ipip_token=ipip_token,
        timeout=timeout,
        progress_callback=progress_callback,
    )

    df.attrs.setdefault("resolved_provider", provider)
    if _has_successful_lookup(df):
        _save_cache(cache_key, df)
    return df


def get_abuse_risk_level(score: int) -> str:
    for threshold, label in ABUSE_CONFIDENCE_LEVELS:
        if score >= threshold:
            return label
    return "未知"


def lookup_abuseipdb_batch(
    ip_list: list[str],
    api_key: str,
    timeout: int = 15,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    base_session = create_retry_session()
    base_session.headers.update(
        {
            "Key": api_key,
            "Accept": "application/json",
            **DEFAULT_HEADERS,
        }
    )

    def lookup_single(ip: str) -> dict:
        session = create_retry_session()
        session.headers.update(base_session.headers)
        try:
            response = session.get(
                ABUSE_IPDB_CHECK_URL,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": "",
                },
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            confidence = int(data.get("abuseConfidenceScore", 0) or 0)
            total_reports = int(data.get("totalReports", 0) or 0)
            time.sleep(ABUSE_DELAY)
            return {
                "IP": ip,
                "恶意IP": "是" if confidence > 0 and total_reports > 0 else "否",
                "风险等级": get_abuse_risk_level(confidence),
                "风险分": confidence,
                "近90天举报次数": total_reports,
                "最近举报时间": data.get("lastReportedAt", ""),
                "使用类型": data.get("usageType", ""),
                "域名": data.get("domain", ""),
                "运营商英文": data.get("isp", ""),
                "是否白名单": "是" if data.get("isWhitelisted") else "否",
            }
        except Exception:
            time.sleep(ABUSE_DELAY)
            return {
                "IP": ip,
                "恶意IP": "未知",
                "风险等级": "未知",
                "风险分": 0,
                "近90天举报次数": 0,
                "最近举报时间": "",
                "使用类型": "",
                "域名": "",
                "运营商英文": "",
                "是否白名单": "否",
            }

    return _concurrent_batch_lookup(ip_list, lookup_single, max_workers=6, progress_callback=progress_callback)


def lookup_ipip_risk_batch(
    ip_list: list[str],
    token: str,
    timeout: int = 15,
    progress_callback: Callable[[int, int], None] | None = None,
) -> pd.DataFrame:
    def lookup_single(ip: str) -> dict:
        session = create_retry_session()
        try:
            response = session.get(
                f"{IPIP_RISK_URL}{ip}",
                params={"token": token},
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if payload.get("ret") != "ok":
                raise requests.RequestException(payload.get("msg", "IPIP 风险画像查询失败"))

            data = payload.get("data", {})
            risk = data.get("risk", {})
            score = int(risk.get("score", 0) or 0)
            behaviors = risk.get("behavior", []) or []
            behavior_names = "、".join(item.get("name", "") for item in behaviors if item.get("name"))
            time.sleep(IPIP_DELAY)
            return {
                "IP": data.get("ip", ip),
                "恶意IP": "是" if score >= 90 else "否",
                "风险等级": get_abuse_risk_level(score),
                "风险分": score,
                "风险行为": behavior_names,
                "IP类型": data.get("usage_type", ""),
            }
        except Exception:
            time.sleep(IPIP_DELAY)
            return {
                "IP": ip,
                "恶意IP": "未知",
                "风险等级": "未知",
                "风险分": 0,
                "风险行为": "",
                "IP类型": "",
            }

    return _concurrent_batch_lookup(ip_list, lookup_single, max_workers=8, progress_callback=progress_callback)


def dataframe_to_excel_bytes(df: pd.DataFrame) -> bytes:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="IP归属地结果")
    buffer.seek(0)
    return buffer.read()


def save_history(result_df: pd.DataFrame, provider: str, abuse_enabled: bool) -> str:
    os.makedirs(HISTORY_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    record_id = f"history_{timestamp}"
    record_path = os.path.join(HISTORY_DIR, f"{record_id}.json")

    record = {
        "id": record_id,
        "timestamp": timestamp,
        "provider": provider,
        "abuse_enabled": abuse_enabled,
        "ip_count": len(result_df),
        "columns": result_df.columns.tolist(),
        "data": result_df.to_dict(orient="records"),
    }

    try:
        with open(record_path, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Cleanup old history
    try:
        files = sorted(
            [f for f in os.listdir(HISTORY_DIR) if f.startswith("history_") and f.endswith(".json")],
            reverse=True,
        )
        for old_file in files[MAX_HISTORY_ITEMS:]:
            os.remove(os.path.join(HISTORY_DIR, old_file))
    except Exception:
        pass

    return record_id


def load_history_list() -> list[dict]:
    if not os.path.exists(HISTORY_DIR):
        return []
    try:
        files = sorted(
            [f for f in os.listdir(HISTORY_DIR) if f.startswith("history_") and f.endswith(".json")],
            reverse=True,
        )
        records = []
        for filename in files:
            path = os.path.join(HISTORY_DIR, filename)
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            records.append(
                {
                    "id": data.get("id", filename),
                    "timestamp": data.get("timestamp", ""),
                    "provider": data.get("provider", ""),
                    "abuse_enabled": data.get("abuse_enabled", False),
                    "ip_count": data.get("ip_count", 0),
                }
            )
        return records
    except Exception:
        return []


def load_history_record(record_id: str) -> pd.DataFrame | None:
    path = os.path.join(HISTORY_DIR, f"{record_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        df = pd.DataFrame(data.get("data", []))
        df.attrs["resolved_provider"] = data.get("provider", "")
        return df
    except Exception:
        return None


def diff_dataframes(old_df: pd.DataFrame, new_df: pd.DataFrame) -> dict:
    old_ips = set(old_df["IP"].dropna().astype(str)) if "IP" in old_df.columns else set()
    new_ips = set(new_df["IP"].dropna().astype(str)) if "IP" in new_df.columns else set()

    added = sorted(new_ips - old_ips)
    removed = sorted(old_ips - new_ips)
    common = old_ips & new_ips

    changed: list[dict] = []
    if common and not old_df.empty and not new_df.empty:
        old_indexed = old_df.set_index("IP")
        new_indexed = new_df.set_index("IP")
        for ip in common:
            if ip not in old_indexed.index or ip not in new_indexed.index:
                continue
            old_row = old_indexed.loc[ip].to_dict()
            new_row = new_indexed.loc[ip].to_dict()
            diffs = {k: {"old": old_row.get(k), "new": new_row.get(k)} for k in old_row if old_row.get(k) != new_row.get(k)}
            if diffs:
                changed.append({"IP": ip, "diffs": diffs})

    return {"added": added, "removed": removed, "changed": changed}
