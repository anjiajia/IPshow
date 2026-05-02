from __future__ import annotations

import time

import pandas as pd
import requests
import streamlit as st

from core import (
    SUPPORTED_PROVIDERS,
    AppConfig,
    ParseResult,
    dataframe_to_excel_bytes,
    diff_dataframes,
    extract_ips_from_upload,
    load_history_list,
    load_history_record,
    lookup_abuseipdb_batch,
    lookup_ip_batch,
    lookup_ipip_risk_batch,
    normalize_lines,
    save_history,
    validate_ip_list,
)

st.set_page_config(page_title="IP 批量归属地查询", page_icon="🌐", layout="wide")
st.title("IP 批量归属地查询")
st.caption("支持手动输入或文件导入，批量查询后可直接阅览，并导出 Excel。")

config = AppConfig.load()

with st.sidebar:
    st.subheader("使用说明")
    st.markdown(
        "\n".join(
            [
                "1. 在左侧导入 `TXT / CSV / XLS / XLSX`，或直接粘贴 IP。",
                "2. 支持 CIDR 格式（如 `192.168.1.0/24`），会自动展开。",
                "3. 点击 `开始查询` 后批量请求归属地数据。",
                "4. 查询结果可在页面浏览，并下载为 Excel。",
            ]
        )
    )
    st.info("支持多数据源查询。推荐使用 IPIP，中文字段更完整，也更适合中国网络环境。")
    ipip_token = st.text_input(
        "IPIP Token（推荐）",
        value=config.ipip_token,
        type="password",
        help="用于 IPIP 中文归属地查询。自动模式下填写后会优先使用 IPIP。",
    )
    provider = st.selectbox(
        "查询数据源",
        options=list(SUPPORTED_PROVIDERS.keys()),
        format_func=lambda key: SUPPORTED_PROVIDERS[key],
        index=list(SUPPORTED_PROVIDERS.keys()).index(config.provider)
        if config.provider in SUPPORTED_PROVIDERS
        else 0,
        help="推荐使用自动模式：若填写了 IPIP Token，则优先走 IPIP；否则回退免费接口。",
    )
    if provider == "auto":
        if ipip_token:
            st.success("当前使用自动模式：先试 IPIP，失败时再回退到免费接口。")
        else:
            st.warning("当前使用自动模式，但未填写 IPIP Token；将只使用免费接口回退链。")
    elif provider == "ipip":
        st.success("当前使用 IPIP，适合中文归属地展示。")
    elif provider == "ip_sb":
        st.warning("当前使用 IP.SB，归属地字段以英文为主，国家会尽量转成中文。")
    else:
        st.success("当前使用 ip-api，支持中文归属地字段，但国内网络环境下可能不稳定。")
    ipip_risk_token = st.text_input(
        "IPIP 风险画像 Token（可选）",
        value=config.ipip_risk_token,
        type="password",
        help="用于识别恶意 IP、代理、机房等风险画像。可与上面的 Token 相同，取决于你的套餐权限。",
    )
    abuse_api_key = st.text_input(
        "AbuseIPDB API Key（可选）",
        value=config.abuse_api_key,
        type="password",
        help="国际备用恶意 IP 检测。更推荐国内环境优先使用 IPIP 风险画像。",
    )
    if ipip_risk_token:
        st.info("已启用 IPIP 风险画像：结果中会附加恶意IP、风险分、风险行为等字段。")
    elif abuse_api_key:
        st.info("已启用 AbuseIPDB 恶意 IP 检测：将附加风险分、举报次数、风险等级等字段。")
    else:
        st.caption("未填写风险画像 Token：暂不检测恶意 IP。")

    if st.button("保存当前配置", use_container_width=True):
        AppConfig(
            ipip_token=ipip_token,
            provider=provider,
            ipip_risk_token=ipip_risk_token,
            abuse_api_key=abuse_api_key,
        ).save()
        st.success("配置已保存到本地。")

    st.divider()
    st.subheader("查询历史")
    history_records = load_history_list()
    if history_records:
        history_options = {f"{r['timestamp']} ({r['ip_count']} 条, {r['provider']})": r["id"] for r in history_records}
        selected_history_label = st.selectbox("加载历史记录", options=[""] + list(history_options.keys()))
        if selected_history_label and selected_history_label in history_options:
            if st.button("加载选中记录", use_container_width=True):
                loaded_df = load_history_record(history_options[selected_history_label])
                if loaded_df is not None:
                    st.session_state["result_df"] = loaded_df
                    st.session_state["last_provider"] = loaded_df.attrs.get("resolved_provider", provider)
                    st.session_state["abuse_enabled"] = any(
                        col in loaded_df.columns for col in ["恶意IP", "风险分"]
                    )
                    st.success("历史记录已加载。")
                    st.rerun()
                else:
                    st.error("加载历史记录失败。")
    else:
        st.caption("暂无查询历史。")

left, right = st.columns([1, 1])

with left:
    uploaded_file = st.file_uploader(
        "导入 IP 文件",
        type=["txt", "csv", "xls", "xlsx"],
        help="TXT 可按换行或逗号分隔；表格文件会自动读取所有单元格中的 IP。支持 CIDR（如 192.168.1.0/24）。",
    )
    manual_text = st.text_area(
        "或手动输入 IP",
        height=240,
        placeholder="示例：\n8.8.8.8\n1.1.1.1\n223.5.5.5\n192.168.1.0/24",
    )

raw_values: list[str] = []
if uploaded_file is not None:
    try:
        raw_values.extend(extract_ips_from_upload(uploaded_file))
    except Exception as exc:
        st.error(f"文件解析失败：{exc}")

if manual_text.strip():
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
        progress = st.progress(0, text="正在批量查询 IP 归属地...")

        def update_progress(current: int, total: int) -> None:
            ratio = 0 if total == 0 else current / total
            progress.progress(ratio, text=f"正在批量查询 IP 归属地... {current}/{total}")

        with st.spinner("正在批量查询 IP 归属地..."):
            result_df = lookup_ip_batch(
                parse_result.ips,
                provider=provider,
                ipip_token=ipip_token,
                progress_callback=update_progress,
            )
        if ipip_risk_token:
            progress.progress(0, text="正在检测 IP 风险画像...")

            def update_ipip_risk_progress(current: int, total: int) -> None:
                ratio = 0 if total == 0 else current / total
                progress.progress(ratio, text=f"正在检测 IP 风险画像... {current}/{total}")

            ipip_risk_df = lookup_ipip_risk_batch(
                parse_result.ips,
                token=ipip_risk_token,
                progress_callback=update_ipip_risk_progress,
            )
            result_df = result_df.merge(ipip_risk_df, on="IP", how="left", suffixes=("", "_风险"))
            if "IP类型_风险" in result_df.columns:
                if "IP类型" in result_df.columns:
                    result_df["IP类型"] = result_df["IP类型_风险"].combine_first(result_df["IP类型"])
                else:
                    result_df["IP类型"] = result_df["IP类型_风险"]
                result_df = result_df.drop(columns=["IP类型_风险"])
        elif abuse_api_key:
            progress.progress(0, text="正在检测恶意 IP 风险...")

            def update_abuse_progress(current: int, total: int) -> None:
                ratio = 0 if total == 0 else current / total
                progress.progress(ratio, text=f"正在检测恶意 IP 风险... {current}/{total}")

            abuse_df = lookup_abuseipdb_batch(
                parse_result.ips,
                api_key=abuse_api_key,
                progress_callback=update_abuse_progress,
            )
            result_df = result_df.merge(abuse_df, on="IP", how="left")
        progress.empty()
        st.session_state["result_df"] = result_df
        st.session_state["last_provider"] = result_df.attrs.get("resolved_provider", provider)
        st.session_state["abuse_enabled"] = bool(ipip_risk_token or abuse_api_key)

        # Save to history
        try:
            save_history(
                result_df,
                provider=result_df.attrs.get("resolved_provider", provider),
                abuse_enabled=bool(ipip_risk_token or abuse_api_key),
            )
        except Exception:
            pass
    except requests.RequestException as exc:
        st.error(f"查询失败：{exc}")
    except ValueError as exc:
        st.error(str(exc))

result_df = st.session_state.get("result_df")
if isinstance(result_df, pd.DataFrame) and not result_df.empty:
    st.divider()
    st.subheader("查询结果")
    last_provider = st.session_state.get("last_provider", provider)
    st.caption(f"当前展示结果来自：{SUPPORTED_PROVIDERS.get(last_provider, last_provider)}")
    if st.session_state.get("abuse_enabled"):
        st.caption("已附加恶意 IP 检测结果。")

    # Visualization
    with st.expander("📊 数据可视化", expanded=False):
        viz_cols = st.columns(2)

        with viz_cols[0]:
            if "国家" in result_df.columns:
                country_counts = result_df["国家"].replace("", "未知").value_counts().head(10)
                if not country_counts.empty:
                    st.write("**国家/地区分布（Top 10）**")
                    st.bar_chart(country_counts)

            if "查询状态" in result_df.columns:
                status_counts = result_df["查询状态"].value_counts()
                if not status_counts.empty:
                    st.write("**查询状态分布**")
                    status_df = status_counts.reset_index()
                    status_df.columns = ["状态", "数量"]
                    st.bar_chart(status_df.set_index("状态"))

        with viz_cols[1]:
            if "运营商" in result_df.columns:
                isp_counts = result_df["运营商"].replace("", "未知").value_counts().head(10)
                if not isp_counts.empty:
                    st.write("**运营商分布（Top 10）**")
                    st.bar_chart(isp_counts)

            if "恶意IP" in result_df.columns:
                malicious_counts = result_df["恶意IP"].value_counts()
                if not malicious_counts.empty:
                    st.write("**恶意 IP 分布**")
                    mal_df = malicious_counts.reset_index()
                    mal_df.columns = ["恶意IP", "数量"]
                    st.bar_chart(mal_df.set_index("恶意IP"))

        if "纬度" in result_df.columns and "经度" in result_df.columns:
            map_df = result_df[["纬度", "经度"]].copy()
            map_df = map_df[map_df["纬度"].astype(str).str.replace(".", "", 1).str.isdigit()]
            map_df = map_df[map_df["经度"].astype(str).str.replace(".", "", 1).str.isdigit()]
            if not map_df.empty:
                map_df = map_df.rename(columns={"纬度": "lat", "经度": "lon"}).astype(float)
                st.write("**IP 地理分布地图**")
                st.map(map_df)

    # Diff / Compare
    with st.expander("🔍 结果对比", expanded=False):
        history_records = load_history_list()
        if len(history_records) >= 1:
            compare_options = {f"{r['timestamp']} ({r['ip_count']} 条)": r["id"] for r in history_records}
            compare_label = st.selectbox("选择要对比的历史记录", options=[""] + list(compare_options.keys()))
            if compare_label and compare_label in compare_options:
                old_df = load_history_record(compare_options[compare_label])
                if old_df is not None and not old_df.empty:
                    diff = diff_dataframes(old_df, result_df)
                    diff_cols = st.columns(3)
                    diff_cols[0].metric("新增 IP", len(diff["added"]))
                    diff_cols[1].metric("移除 IP", len(diff["removed"]))
                    diff_cols[2].metric("变化 IP", len(diff["changed"]))
                    if diff["added"]:
                        st.write("**新增 IP：**")
                        st.code(", ".join(diff["added"]))
                    if diff["removed"]:
                        st.write("**移除 IP：**")
                        st.code(", ".join(diff["removed"]))
                    if diff["changed"]:
                        st.write(f"**字段变化的 IP（共 {len(diff['changed'])} 条）：**")
                        for item in diff["changed"][:10]:
                            st.markdown(f"- `{item['IP']}`")
                        if len(diff["changed"]) > 10:
                            st.caption(f"... 还有 {len(diff['changed']) - 10} 条变化未展示")
                else:
                    st.warning("选中的历史记录为空或加载失败。")
        else:
            st.caption("需要至少两条历史记录才能进行对比。")

    status_options = ["全部"] + sorted(result_df["查询状态"].dropna().unique().tolist())
    selected_status = st.selectbox("按查询状态筛选", status_options, index=0)

    view_df = result_df
    if selected_status != "全部":
        view_df = result_df[result_df["查询状态"] == selected_status].copy()

    st.dataframe(view_df, use_container_width=True, height=420, hide_index=True)

    download_cols = st.columns(2)
    with download_cols[0]:
        excel_bytes = dataframe_to_excel_bytes(view_df)
        st.download_button(
            "导出当前结果为 Excel",
            data=excel_bytes,
            file_name="ip_geolocation_results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )
    with download_cols[1]:
        csv_bytes = view_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "导出当前结果为 CSV",
            data=csv_bytes,
            file_name="ip_geolocation_results.csv",
            mime="text/csv",
            use_container_width=True,
        )
