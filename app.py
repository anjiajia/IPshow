from __future__ import annotations

import io
import ipaddress
from dataclasses import dataclass
from typing import Iterable

import pandas as pd
import requests
import streamlit as st


API_BATCH_URL = "http://ip-api.com/batch"
API_FIELDS = ",".join(
    [
        "status",
        "message",
        "query",
        "country",
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


@dataclass
class ParseResult:
    ips: list[str]
    invalid_values: list[str]


def normalize_lines(raw_text: str) -> list[str]:
    return [
        item.strip()
        for line in raw_text.splitlines()
        for item in line.replace("，", ",").replace(";", ",").split(",")
        if item.strip()
    ]


def validate_ip_list(values: Iterable[str]) -> ParseResult:
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()

    for value in values:
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            invalid.append(value)
            continue

        if ip not in seen:
            seen.add(ip)
            valid.append(ip)

    return ParseResult(ips=valid, invalid_values=invalid)


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


def lookup_ip_batch(ip_list: list[str], timeout: int = 15) -> pd.DataFrame:
    rows: list[dict] = []

    for chunk in batched(ip_list, MAX_BATCH_SIZE):
        payload = [{"query": ip, "fields": API_FIELDS, "lang": "zh-CN"} for ip in chunk]
        response = requests.post(API_BATCH_URL, json=payload, timeout=timeout)
        response.raise_for_status()

        for item in response.json():
            rows.append(
                {
                    "IP": item.get("query", ""),
                    "查询状态": item.get("status", ""),
                    "错误信息": item.get("message", ""),
                    "国家": item.get("country", ""),
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

    return pd.DataFrame(rows)


def dataframe_to_excel_bytes(df: pd.DataFrame) -> bytes:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="IP归属地结果")
    buffer.seek(0)
    return buffer.read()


st.set_page_config(page_title="IP 批量归属地查询", page_icon="🌐", layout="wide")
st.title("IP 批量归属地查询")
st.caption("支持手动输入或文件导入，批量查询后可直接阅览，并导出 Excel。")

with st.sidebar:
    st.subheader("使用说明")
    st.markdown(
        "\n".join(
            [
                "1. 在左侧导入 `TXT / CSV / XLS / XLSX`，或直接粘贴 IP。",
                "2. 点击 `开始查询` 后批量请求归属地数据。",
                "3. 查询结果可在页面浏览，并下载为 Excel。",
            ]
        )
    )
    st.info("免费接口来自 ip-api，单次批量最多 100 个 IP，应用会自动分批处理。")

left, right = st.columns([1, 1])

with left:
    uploaded_file = st.file_uploader(
        "导入 IP 文件",
        type=["txt", "csv", "xls", "xlsx"],
        help="TXT 可按换行或逗号分隔；表格文件会自动读取所有单元格中的 IP。",
    )
    manual_text = st.text_area(
        "或手动输入 IP",
        height=240,
        placeholder="示例：\n8.8.8.8\n1.1.1.1\n223.5.5.5",
    )

raw_values: list[str] = []
if uploaded_file is not None:
    try:
        raw_values.extend(extract_ips_from_upload(uploaded_file))
    except Exception as exc:
        st.error(f"文件解析失败：{exc}")

raw_values.extend(normalize_lines(manual_text))
parse_result = validate_ip_list(raw_values)

with right:
    st.subheader("待查询概览")
    metric_cols = st.columns(3)
    metric_cols[0].metric("有效 IP", len(parse_result.ips))
    metric_cols[1].metric("无效内容", len(parse_result.invalid_values))
    metric_cols[2].metric("去重后总数", len(parse_result.ips))

    if parse_result.ips:
        st.dataframe(
            pd.DataFrame({"IP": parse_result.ips}),
            use_container_width=True,
            height=260,
            hide_index=True,
        )
    else:
        st.write("暂无可查询 IP。")

if parse_result.invalid_values:
    with st.expander("查看无效内容"):
        st.write(pd.DataFrame({"无效值": parse_result.invalid_values}))

query_button = st.button("开始查询", type="primary", disabled=not parse_result.ips)

if query_button:
    try:
        with st.spinner("正在批量查询 IP 归属地..."):
            result_df = lookup_ip_batch(parse_result.ips)
        st.session_state["result_df"] = result_df
    except requests.RequestException as exc:
        st.error(f"查询失败：{exc}")

result_df = st.session_state.get("result_df")
if isinstance(result_df, pd.DataFrame) and not result_df.empty:
    st.divider()
    st.subheader("查询结果")

    status_options = ["全部"] + sorted(result_df["查询状态"].dropna().unique().tolist())
    selected_status = st.selectbox("按查询状态筛选", status_options, index=0)

    view_df = result_df
    if selected_status != "全部":
        view_df = result_df[result_df["查询状态"] == selected_status].copy()

    st.dataframe(view_df, use_container_width=True, height=420, hide_index=True)

    excel_bytes = dataframe_to_excel_bytes(view_df)
    st.download_button(
        "导出当前结果为 Excel",
        data=excel_bytes,
        file_name="ip_geolocation_results.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

    csv_bytes = view_df.to_csv(index=False).encode("utf-8-sig")
    st.download_button(
        "导出当前结果为 CSV",
        data=csv_bytes,
        file_name="ip_geolocation_results.csv",
        mime="text/csv",
    )
