/**
 * @file Clash 配置文件动态生成脚本
 * @author YourName (可以替换为你的名字)
 * @version 2.5.0
 * @description
 * 该脚本用于动态生成和修改 Clash (Mihomo 内核) 配置文件。
 * 主要功能包括：
 * 1. 覆写基础配置：设置混合端口、局域网访问、并发TCP、统一延迟等。
 * 2. 增强嗅探功能：优化 DNS 处理，提升路由规则匹配的准确性。
 * 3. 自动节点分组：根据节点名称中的地区关键字，自动创建多种策略组（手动选择、自动选择、故障转移等）。
 * 4. 规则集管理：引入外部规则集，并按 广告拦截 -> 自定义 -> 代理 -> 直连 -> IP规则 -> 兜底 的顺序进行组织。
 * 5. DNS 深度优化：配置 Fake IP 模式，并为国内外域名、代理服务器域名设置不同的解析策略，防止 DNS 污染。
 * 6. TUN 模式配置：创建虚拟网卡以接管系统流量，并设置 DNS 劫持。
 */

// --- 用户自定义区域 ---

/**
 * 策略组连通性检查 URL (Speed Test URL)
 * - 用于 `select` 和 `fallback` 等策略组，判断节点是否可用。
 * - 建议使用响应快、稳定、内容少的 URL。
 * - 常见选项：
 * "http://www.gstatic.com/generate_204" (Google)
 * "http://cp.cloudflare.com/" (Cloudflare)
 * "http://detectportal.firefox.com/success.txt" (Mozilla)
 */
const speedTestUrl = "http://www.gstatic.com/generate_204";


/**
 * 用户自定义规则 (User Custom Rules)
 * - 规则会插入在 “广告拦截” 之后，“常规代理规则” 之前，拥有较高的匹配优先级。
 * - 格式为 Clash 标准规则格式，例如：
 * "DOMAIN-SUFFIX,google.com,代理模式"  // google.com 及其子域名走“代理模式”策略组
 * "RULE-SET,规则集名称,策略组名称"
 * "DOMAIN": 精确匹配域名
 * "DOMAIN-SUFFIX": 匹配域名后缀
 * "DOMAIN-KEYWORD": 匹配域名关键字
 * "IP-CIDR": 匹配 IP 地址段
 * "GEOIP": 匹配国家/地区 IP
 * "FINAL": 兜底规则，当所有规则都未匹配时使用
 */
const AddCustomization = [
    "DOMAIN-KEYWORD,upai,代理模式",
    "DOMAIN-SUFFIX,ipinfo.io,代理模式",
    "DOMAIN-SUFFIX,ipdata.co,代理模式",
    "PROCESS-NAME,org.zwanoo.android.speedtest,代理模式",//speed test包名
    "DOMAIN-SUFFIX,jianguoyun.com,DIRECT",

    // "DOMAIN-SUFFIX,900cha.com,代理模式", // 示例
];


// --- 脚本主逻辑 ---

/**
 * 脚本主函数 (Main Function)
 * @param {object} params - 原始 Clash 配置文件对象。
 * @returns {object} - 修改后的 Clash 配置文件对象。
 */
function main(params) {
    // 检查是否存在代理节点，如果不存在则在日志中警告
    if (!params.proxies || params.proxies.length === 0) {
        console.warn("配置文件中没有找到代理节点，部分策略组可能为空。");
    }
    
    // 依次调用各个模块的覆写函数
    overwriteBasicOptions(params);
    overwriteSniffer(params);
    overwriteProxyGroups(params);
    overwriteRules(params);
    overwriteDns(params);
    overwriteTunnel(params);
    
    return params;
}


// --- 各模块覆写函数 ---

/**
 * 覆写基础配置 (Basic Options)
 * @param {object} params - Clash 配置文件对象
 */
function overwriteBasicOptions(params) {
    const basicOptions = {
        "mixed-port": 7890,         // HTTP 和 SOCKS5 混合代理端口
        "allow-lan": true,          // 允许来自局域网的连接
        "unified-delay": true,      // 对所有节点使用统一的延迟测速 URL
        "tcp-concurrent": true,     // 增强 TCP 并发，可提高网页加载速度
        "geodata-mode": true,       // 使用 GeoIP 数据库 mmdb
        "mode": "rule",             // 默认使用规则模式
        "ipv6": false,              // 禁用 IPv6，以更好地兼容 Fake IP 模式，避免潜在问题
        
        // Profile 相关设置，用于持久化状态
        "profile": {
            "store-selected": true, // 记住策略组的手动选择
            "store-fake-ip": true,  // 持久化 Fake IP 映射
        },
        
        // 客户端指纹伪装，用于模拟 Chrome 浏览器发出的 TLS 请求
        "global-client-fingerprint": "chrome",
        
        // Fake IP 行为模式，strict 模式下仅处理 DNS 请求中包含的域名
        "fakeip-process-mode": "strict",
        
        // 局域网白名单，"0.0.0.0/0" 表示允许所有 IP 连接，安全性较低。
        // 如需增强安全性，可替换为具体的私有网段，例如：
        // "lan-allowed-ips": ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]
        "lan-allowed-ips": ["0.0.0.0/0", "::/0"],
        
        // 跳过认证的前缀，通常用于本机服务
        "skip-auth-prefixes": ["127.0.0.1/32"],
    };
    Object.assign(params, basicOptions);
}

/**
 * 覆写嗅探配置 (Sniffer)
 * Sniffer 用于识别流量的域名，从而应用更精确的域名规则。
 * @param {object} params - Clash 配置文件对象
 */
function overwriteSniffer(params) {
    const snifferConfig = {
        "enable": true,             // 启用嗅探
        "force-dns-mapping": true,  // 强制将嗅探到的域名进行 DNS 解析
        "parse-pure-ip": true,      // 嗅探纯 IP 流量的域名
        "override-destination": false, // 是否覆盖原始目标地址，关闭以避免 UDP 问题
        "sniff": {
            "HTTP": { "ports": ["80", "443"], "override-destination": false },
            "TLS": { "ports": ["443"] },
        },
        // 跳过嗅探的域名，例如 Apple 的推送服务
        "skip-domain": ["+.push.apple.com"],
        // 跳过嗅探的目标 IP 地址段，通常是 Telegram 的 IP
        "skip-dst-address": [
            "91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/21",
            "91.108.16.0/21", "91.108.56.0/22", "95.161.64.0/20",
            "149.154.160.0/20", "185.76.151.0/24", "2001:67c:4e8::/48",
            "2001:b28:f23c::/47", "2001:b28:f23f::/48", "2a0a:f280:203::/48",
        ]
    };
    params["sniffer"] = snifferConfig;
}

/**
 * 覆写代理组 (Proxy Groups)
 * 自动将代理节点按地区分组，并创建多种负载均衡策略组。
 * @param {object} params - Clash 配置文件对象
 */
function overwriteProxyGroups(params) {
    // 您可以在此手动添加自用代理，格式如下
    // params.proxies.push({
    //     name: '1 - 香港 - 示例',
    //     type: 'ss',
    //     server: 'example.com',
    //     port: 8443,
    //     cipher: 'aes-256-gcm',
    //     password: 'password',
    //     udp: true
    // });

    // 代理地区配置：用于通过正则表达式匹配节点名称，实现自动分组
    const countryRegions = [
        { code: "HK", name: "🇭🇰 香港", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg", regex: /(香港|HK|Hong Kong|🇭🇰)/i },
        { code: "TW", name: "🇹🇼 台湾", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg", regex: /(台湾|TW|Taiwan|🇹🇼)/i },
        { code: "SG", name: "🇸🇬 新加坡", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg", regex: /(新加坡|狮城|SG|Singapore|🇸🇬)/i },
        { code: "JP", name: "🇯🇵 日本", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/jp.svg", regex: /(日本|JP|Japan|🇯🇵)/i },
        { code: "KR", name: "🇰🇷 韩国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/kr.svg", regex: /(韩国|KR|Korea|South Korea|🇰🇷)/i },
        { code: "US", name: "🇺🇸 美国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg", regex: /(美国|US|USA|United States|America|🇺🇸)/i },
        /*
        { code: "DE", name: "🇩🇪 德国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/de.svg", regex: /(德国|DE|Germany|🇩🇪)/i },
        { code: "UK", name: "🇬🇧 英国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/gb.svg", regex: /(英国|UK|United Kingdom|Britain|Great Britain|🇬🇧)/i },
        { code: "CA", name: "🇨🇦 加拿大", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ca.svg", regex: /(加拿大|CA|Canada|🇨🇦)/i },
        { code: "AU", name: "🇦🇺 澳大利亚", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/au.svg", regex: /(澳大利亚|AU|Australia|🇦🇺)/i },
        { code: "FR", name: "🇫🇷 法国", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/fr.svg", regex: /(法国|FR|France|🇫🇷)/i },
        { code: "IT", name: "🇮🇹 意大利", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/it.svg", regex: /(意大利|IT|Italy|🇮🇹)/i },
        { code: "BR", name: "🇧🇷 巴西", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/br.svg", regex: /(巴西|BR|Brazil|🇧🇷)/i },
        { code: "RU", name: "🇷🇺 俄罗斯", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ru.svg", regex: /(俄罗斯|RU|Russia|🇷🇺)/i },
        { code: "IN", name: "🇮🇳 印度", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/in.svg", regex: /\b(印度|IN|India|🇮🇳)\b/i },
        { code: "CH", name: "🇨🇭 瑞士", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ch.svg", regex: /(瑞士|CH|Switzerland|🇨🇭)/i },
        { code: "SE", name: "🇸🇪 瑞典", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/se.svg", regex: /(瑞典|SE|Sweden|🇸🇪)/i },
        { code: "NO", name: "🇳🇴 挪威", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/no.svg", regex: /(挪威|NO|Norway|🇳🇴)/i },
        { code: "TR", name: "🇹🇷 土耳其", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tr.svg", regex: /(土耳其|TR|Turkey|🇹🇷)/i },
        { code: "AR", name: "🇦🇷 阿根廷", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/ar.svg", regex: /(阿根廷|AR|Argentina|🇦🇷)/i },
        { code: "ES", name: "🇪🇸 西班牙", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/es.svg", regex: /\b(西班牙|ES|Spain|🇪🇸)\b/i },
        { code: "NL", name: "🇳🇱 荷兰", icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/nl.svg", regex: /\b(荷兰|NL|Netherlands|🇳🇱)\b/i },
        */
        // 兜底选项，用于匹配所有其他未分类的节点
        { name: "其他", regex: null, icon: "https://raw.githubusercontent.com/clash-verge-rev/clash-verge-rev.github.io/refs/heads/main/docs/assets/icons/link.svg" },

    ];

    // 获取所有代理节点的名称
    const allProxies = params.proxies ? params.proxies.map(p => p.name) : [];

    // 1. 将代理节点按地区分组
    const groupedProxies = {};
    const otherProxies = []; // 存储未匹配到任何地区的节点
    const specificRegions = countryRegions.filter(region => region.regex !== null);

    if (params.proxies) {
        params.proxies.forEach(proxy => {
            let matched = false;
            for (const region of specificRegions) {
                if (region.regex.test(proxy.name)) {
                    if (!groupedProxies[region.name]) {
                        groupedProxies[region.name] = [];
                    }
                    groupedProxies[region.name].push(proxy.name);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                otherProxies.push(proxy.name);
            }
        });
    }

    if (otherProxies.length > 0) {
        groupedProxies["其他"] = otherProxies;
    }

    // 2. 创建地区策略组
    const availableRegions = countryRegions.filter(region => groupedProxies[region.name] && groupedProxies[region.name].length > 0);
    
    const autoProxyGroups = availableRegions.map(region => ({
        name: `${region.name} - 自动选择`,
        type: "fallback",
        url: speedTestUrl,
        interval: 300,
        tolerance: 50,
        proxies: groupedProxies[region.name],
        hidden: true,
    }));
    
    const manualProxyGroups = availableRegions.map(region => ({
        name: `${region.name} - 手动选择`,
        type: "select",
        proxies: groupedProxies[region.name],
        icon: region.icon,
    }));

    const mainProxyGroupNames = availableRegions.flatMap(region => [
        `${region.name} - 自动选择`,
        `${region.name} - 手动选择`,
    ]);

    // 3. 创建功能性策略组
    const groups = [
        // 主策略组
        {
            name: "代理模式",
            type: "select",
            url: speedTestUrl,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg",
            proxies: [
                "延迟优选", 
                "故障转移", 
                "负载均衡 (散列)", 
                "负载均衡 (轮询)",
                ...mainProxyGroupNames
            ],
        },
        // 核心负载均衡策略组
        {
            name: "延迟优选",
            type: "url-test",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/speed.svg",
            "exclude-filter": "自动选择|手动选择",
            proxies: allProxies,
            hidden: true,
        },
        {
            name: "故障转移",
            type: "fallback",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/ambulance.svg",
            "exclude-filter": "自动选择|手动选择",
            proxies: allProxies,
            hidden: true,
        },
        {
            name: "负载均衡 (散列)",
            type: "load-balance",
            strategy: "consistent-hashing",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/balance.svg",
            "exclude-filter": "自动选择|手动选择",
            proxies: allProxies,
            hidden: true,
        },
        {
            name: "负载均衡 (轮询)",
            type: "load-balance",
            strategy: "round-robin",
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/merry_go.svg",
            "exclude-filter": "自动选择|手动选择",
            proxies: allProxies,
            hidden: true,
        },
        {
            name: "电报消息",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg",
        },
        {
            name: "AI",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg",
        },
        {
            name: "流媒体",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/youtube.svg",
        },
        {
            name: "交易所",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/vadimmalykhin/binance-icons@main/crypto/btc.svg",
        },
        {
            name: "Google服务",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/google.svg",
        },
        {
            name: "苹果服务",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/apple.svg",
        },
        {
            name: "微软服务",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/microsoft.svg",
        },
        {
            name: "GoogleFCM",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/google.svg",
        },
        {
            name: "抖音",
            type: "select",
            proxies: ["代理模式", "DIRECT", ...mainProxyGroupNames],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/tiktok.svg",
        },
        // 应用专用策略组
        {
            name: "广告拦截",
            type: "select",
            proxies: ["REJECT", "DIRECT", "代理模式"],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/bug.svg",
        },
        {
            name: "漏网之鱼", // 用于匹配所有其他规则未覆盖的流量
            type: "select",
            proxies: ["代理模式", "DIRECT"],
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg",
        },
    ];
    
    // 4. 合并所有策略组
    groups.push(...autoProxyGroups);
    groups.push(...manualProxyGroups);
    params["proxy-groups"] = groups;
}

/**
 * 覆写规则和规则集 (Rules & Rule Providers)
 * @param {object} params - Clash 配置文件对象
 */
function overwriteRules(params) {
    // --- 规则集 Provider 定义 ---

    // 广告拦截规则集的更新配置 (24小时更新一次)
    const adBlockUpdateAnchor = {
        type: "http",
        interval: 86400, // 24小时更新一次
    };

    const fastUpdateAnchor = {
        type: "http",
        interval: 0, // 为 0 禁用更新
        behavior: "classical",
        format: "yaml",
    };
    const regularUpdateAnchor = {
        type: "http",
        interval: 0, // 为 0 禁用更新
        behavior: "classical",
        format: "yaml",
    };

    const realSeekPath = "https://raw.githubusercontent.com/RealSeek/Clash_Rule_DIY/refs/heads/mihomo/";
    
    // 规则集 Provider 列表
    const ruleProviders = {
        // --- 广告与跟踪拦截 (REJECT) ---
        // 修复：更新为 blackmatrix7 的有效规则链接，并调整 behavior 和 format
        "Advertising": { ...adBlockUpdateAnchor, behavior: "classical", format: "yaml", url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.yaml", path: "./ruleset/blackmatrix7/Advertising.yaml" },
        "Privacy": { ...adBlockUpdateAnchor, behavior: "classical", format: "yaml", url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.yaml", path: "./ruleset/blackmatrix7/Privacy.yaml" },

        "AdBlock_REIJI007": { ...adBlockUpdateAnchor, behavior: "domain", format: "text", url: "https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Sing-box/main/adblock_reject_domain.txt", path: "./ruleset/REIJI007/adblock_reject_domain.yaml" },
        
        // 旧有规则集，更新间隔保持为0，可根据需要开启
        "Reject_ip": { ...fastUpdateAnchor, behavior: "ipcidr", url: realSeekPath + "REJECT/ip/Reject_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/REJECT/ip/Reject_ip.yaml" },
        "Reject_no_ip": { ...fastUpdateAnchor, url: realSeekPath + "REJECT/no_ip/Reject_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/REJECT/no_ip/Reject_no_ip.yaml" },
        
        // --- 直连规则 (DIRECT) ---
        "China_ip": { ...regularUpdateAnchor, behavior: "ipcidr", url: realSeekPath + "DIRECT/ip/China_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/ip/China_ip.yaml" },
        "Domestic_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/ip/Domestic_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/ip/Domestic_ip.yaml" },
        "GoogleFCM_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/ip/GoogleFCM_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/ip/GoogleFCM_ip.yaml" },
        "Lan_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/ip/Lan_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/ip/Lan_ip.yaml" },
        "NetEaseMusic_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/ip/NetEaseMusic_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/ip/NetEaseMusic_ip.yaml" },
        "SteamCN_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/ip/SteamCN_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/ip/SteamCN_ip.yaml" },
        "AppleCDN_no_ip": { ...regularUpdateAnchor, behavior: "domain", url: realSeekPath + "DIRECT/no_ip/AppleCDN_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/AppleCDN_no_ip.yaml" },
        "AppleCN_no_ip": { ...regularUpdateAnchor, behavior: "domain", url: realSeekPath + "DIRECT/no_ip/AppleCN_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/AppleCN_no_ip.yaml" },
        "Direct_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/Direct_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/Direct_no_ip.yaml" },
        "Domestic_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/Domestic_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/Domestic_no_ip.yaml" },
        "GoogleFCM_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/GoogleFCM_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/GoogleFCM_no_ip.yaml" },
        "Lan_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/Lan_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/Lan_no_ip.yaml" },
        "MicrosoftCDN_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/MicrosoftCDN_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/MicrosoftCDN_no_ip.yaml" },
        "NetEaseMusic_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/NetEaseMusic_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/NetEaseMusic_no_ip.yaml" },
        "SteamCN_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/SteamCN_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/SteamCN_no_ip.yaml" },
        
        // --- 代理规则 (PROXY) ---
        "SteamRegion_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "DIRECT/no_ip/SteamRegion_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/DIRECT/no_ip/SteamRegion_no_ip.yaml" },
        "Stream_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/ip/Stream_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/ip/Stream_ip.yaml" },
        "Telegram_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/ip/Telegram_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/ip/Telegram_ip.yaml" },
        "AI_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/AI_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/AI_no_ip.yaml" },
        "Apple_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Apple_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Apple_no_ip.yaml" },
        "CDN_domainset": { ...regularUpdateAnchor, behavior: "domain", url: realSeekPath + "PROXY/no_ip/CDN_domainset.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/CDN_domainset.yaml" },
        "CDN_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/CDN_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/CDN_no_ip.yaml" },
        "CustomProxy_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/CustomProxy_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/CustomProxy_no_ip.yaml" },
        "Download_domainset": { ...regularUpdateAnchor, behavior: "domain", url: realSeekPath + "PROXY/no_ip/Download_domainset.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Download_domainset.yaml" },
        "Download_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Download_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Download_no_ip.yaml" },
        "Global_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Global_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Global_no_ip.yaml" },
        "Microsoft_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Microsoft_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Microsoft_no_ip.yaml" },
        "Steam_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Steam_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Steam_no_ip.yaml" },
        "Stream_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Stream_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Stream_no_ip.yaml" },
        "Telegram_no_ip": { ...regularUpdateAnchor, url: realSeekPath + "PROXY/no_ip/Telegram_no_ip.yaml", path: "./ruleset/RealSeek/Clash_Rule_DIY/PROXY/no_ip/Telegram_no_ip.yaml" },
        "ExchangeApps_no_ip": { ...regularUpdateAnchor, url: "https://raw.githubusercontent.com/gxjxzgx/clash_DIY/refs/heads/main/PROXY/ExchangeApps", path: "./ruleset/gxjxzgx/ExchangeApps_no_ip.yaml" },
        "Google_no_ip": { ...regularUpdateAnchor, url: "https://raw.githubusercontent.com/gxjxzgx/clash_DIY/main/PROXY/google.yaml", path: "./ruleset/gxjxzgx/google.yaml" },
    };
    
    // --- 规则排序 (Rule Order) ---
    // 规则匹配顺序至关重要，依次为：去广告 -> 用户自定义 -> 代理 -> 直连 -> IP规则 -> 兜底
    
    // 1. 广告拦截规则 (最高优先级)
    const adNonipRules = [
        // 修复：更新规则集名称
        "RULE-SET,Advertising,广告拦截",
        "RULE-SET,Privacy,广告拦截",
        "RULE-SET,AdBlock_REIJI007,广告拦截",
        // 以下规则集可作为补充，默认不开启自动更新
        "RULE-SET,ExchangeApps_no_ip,交易所",
        "RULE-SET,Reject_no_ip,广告拦截",
    ];

    // 2. 用户自定义规则
    const customRules = AddCustomization;

    // 3. 代理规则 (基于域名)
    const proxyNonipRules = [
        "RULE-SET,AI_no_ip,AI",
        "PROCESS-NAME,com.ss.android.ugc.aweme,抖音",//抖音包名
        "RULE-SET,Stream_no_ip,流媒体",
        "RULE-SET,Google_no_ip,Google服务",
        "RULE-SET,Telegram_no_ip,电报消息",
        "RULE-SET,Apple_no_ip,苹果服务",
        "RULE-SET,Microsoft_no_ip,微软服务",
        "RULE-SET,Steam_no_ip,代理模式",
        "RULE-SET,SteamRegion_no_ip,代理模式",
        "RULE-SET,CDN_domainset,代理模式",
        "RULE-SET,CDN_no_ip,代理模式",
        "RULE-SET,Download_domainset,代理模式",
        "RULE-SET,Download_no_ip,代理模式",
        "RULE-SET,Global_no_ip,代理模式",
        "RULE-SET,CustomProxy_no_ip,代理模式",
    ];
    
    // 4. 直连规则 (基于域名)
    const directNonipRules = [
        "RULE-SET,GoogleFCM_no_ip,GoogleFCM",
        "RULE-SET,NetEaseMusic_no_ip,DIRECT",
        "RULE-SET,SteamCN_no_ip,DIRECT",
        "RULE-SET,AppleCDN_no_ip,DIRECT",
        "RULE-SET,AppleCN_no_ip,DIRECT",
        "RULE-SET,MicrosoftCDN_no_ip,DIRECT",
        "RULE-SET,Domestic_no_ip,DIRECT",
        "RULE-SET,Direct_no_ip,DIRECT",
        "RULE-SET,Lan_no_ip,DIRECT",
    ];

    // 5. IP 规则 (域名规则匹配失败后，会检查目标 IP)
    const ipRules = [
        "RULE-SET,Reject_ip,广告拦截",
        "RULE-SET,Stream_ip,流媒体",
        "RULE-SET,GoogleFCM_ip,GoogleFCM",
        "RULE-SET,Telegram_ip,电报消息",

        "RULE-SET,NetEaseMusic_ip,DIRECT",
        "RULE-SET,SteamCN_ip,DIRECT",
        "RULE-SET,Domestic_ip,DIRECT",
        "RULE-SET,Lan_ip,DIRECT",
        "GEOIP,CN,DIRECT",          // 中国大陆 IP 直连
        "GEOSITE,cn,DIRECT",        // 中国大陆常用网站直连
        "RULE-SET,China_ip,DIRECT",
        "MATCH,漏网之鱼",           // 兜底规则，所有未匹配的流量都将经过“漏网之鱼”策略组
    ];

    // 6. 合び所有规则
    const rules = [...adNonipRules, ...customRules, ...proxyNonipRules, ...directNonipRules, ...ipRules];
    params.rules = rules;
    params["rule-providers"] = ruleProviders;
}

/**
 * 覆写 DNS 配置 (DNS)
 * 使用 Fake IP 模式并进行深度优化，有效防止 DNS 污染并提高规则匹配精度。
 * @param {object} params - Clash 配置文件对象
 */
function overwriteDns(params) {
  // 国内 DNS 服务器 (DoH)，用于解析国内域名
  const domesticNameservers = [
    "https://223.5.5.5/dns-query", // 阿里 DoH
    "https://doh.pub/dns-query"    // 腾讯 DoH
  ];

  // 国外 DNS 服务器 (DoH)，用于解析国外域名和作为备用
  const foreignNameservers = [
    //"https://1.1.1.1/dns-query",   // Cloudflare
    //"https://8.8.8.8/dns-query",   // Google
    "https://dns.google/dns-query" 
  ];

  const dnsConfig = {
    "enable": true,
    "listen": "0.0.0.0:1053",      // DNS 监听端口，TUN 模式的 DNS 劫持需要指向此端口
    "ipv6": false,                 // 禁用 IPv6 DNS 解析
    "prefer-h3": false,            // 不优先使用 DoH3
    "respect-rules": true,         // 尊重规则中的域名解析策略
    "use-system-hosts": false,     // 不使用系统 hosts 文件
    "cache-algorithm": "arc",      // 使用 ARC 缓存算法
    
    // 核心：增强模式 Fake IP
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16", // Fake IP 的地址池范围
    
    // Fake IP 白名单，这些域名不会被分配 Fake IP，而是返回真实 IP
    "fake-ip-filter": [
      "+.lan",                     // 局域网域名
      "+.local",
      "+.msftconnecttest.com",     // Windows 网络连接状态检测
      "+.msftncsi.com",
      "localhost.ptlogin2.qq.com", // QQ 登录
      "localhost.sec.qq.com",
      "+.in-addr.arpa",
      "+.ip6.arpa",
      "time.*.com",                // NTP 时间服务
      "time.*.gov",
      "pool.ntp.org",
      "localhost.work.weixin.qq.com" // 微信登录
    ],

    // 默认 DNS (无污染，用于 fallback)
    "default-nameserver": [ "1.1.1.1", "8.8.8.8" ],

    // 国外域名解析服务器 (当域名匹配 PROXY 规则时使用)
    "nameserver": [...foreignNameservers],

    // 代理服务器域名解析服务器 (用于解析 `proxies` 中的 server 地址)
    // 优先使用国内 DNS，失败后自动 fallback 到国外 DNS
    "proxy-server-nameserver": [ ...domesticNameservers, ...foreignNameservers ],

    // DNS 策略：匹配到的国内域名走国内 DNS 解析
    "nameserver-policy": {
      "geosite:private,cn": domesticNameservers
    }
  };

  params["dns"] = dnsConfig;
}

/**
 * 覆写 TUN 模式配置 (TUN Mode)
 * 创建一个虚拟网卡，接管系统大部分流量。
 * @param {object} params - Clash 配置文件对象
 */
function overwriteTunnel(params) {
    const tunnelOptions = {
        "enable": true,
        "stack": "mixed", // 自动选择最佳的 TUN 协议栈 (gVisor/System)
        "device": "Mihomo", // 虚拟网卡名称
        
        // 关键：DNS 劫持。将所有设备的 DNS 查询重定向到 Clash 的 DNS 服务器 (1053端口)
        // 必须与 `dns.listen` 配置的端口一致！
        "dns-hijack": [
            "0.0.0.0:1053", // 劫持所有发往 1053 端口的 IPv4 流量
            "::/0:1053"       // 劫持所有发往 1053 端口的 IPv6 流量
        ],
        
        "auto-route": true,              // 自动设置系统路由
        "auto-detect-interface": true,   // 自动检测出口网卡
        "strict-route": false,
    };
    params.tun = tunnelOptions;
}
