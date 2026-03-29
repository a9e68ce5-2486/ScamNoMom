export const TW_SCAM_KEYWORDS = {
  credential: ["驗證", "登入", "登錄", "密碼", "帳戶", "帳號", "身分驗證", "重新登入", "確認帳號", "帳戶異常", "雙重驗證", "驗證碼"],
  urgency: ["立即", "緊急", "停用", "停權", "異常登入", "確認", "補件", "逾期", "失敗", "重新啟用", "點擊連結", "限時", "今日內", "24小時內"],
  payment: ["解除分期", "重複扣款", "付款", "繳費", "匯款", "轉帳", "銀行", "信用卡", "電子支付", "街口", "全支付", "全盈+pay", "退款", "atm", "網銀", "點數卡", "遊戲點數", "代碼繳費"],
  logistics: ["包裹", "物流", "配送", "宅配", "取貨", "超商", "黑貓", "新竹物流", "宅配通", "ezway", "關務署", "包裹異常", "清關"],
  prize: ["中獎", "領獎", "抽獎", "獎金", "贈品", "抽中", "免費領取"],
  investment: ["飆股", "投資群", "帶單", "保證獲利", "穩賺不賠", "虛擬貨幣", "加密貨幣", "入金", "出金", "老師報牌", "投顧", "老師帶你賺", "高報酬", "零風險"],
  customerService: ["客服", "專員", "解除分期", "誤設分期", "訂單錯誤", "重複下單", "訂單異常", "客服中心", "來電處理", "購物客服", "momo客服", "蝦皮客服", "不操作會扣款", "誤植訂單"],
  government: ["監理站", "交通罰單", "罰單", "稅務", "國稅局", "健保署", "勞保局", "法院", "地檢署", "警政署", "政府通知", "戶政", "健保費", "地方法院", "刑事警察", "分局", "檢察官"],
  qr: ["掃碼", "掃描qr code", "qr code", "條碼繳費", "行動條碼", "掃碼登入", "掃碼付款", "line qr", "加好友qr"],
  marketplace: ["賣場", "私下交易", "私訊交易", "先匯款後出貨", "假買家", "貨到付款改匯款", "第三方保證", "保證交易", "二手社團", "社團下單"]
} as const;

export type TwScamKeywordCategory = keyof typeof TW_SCAM_KEYWORDS;

export function hasKeywordMatch(text: string, category: TwScamKeywordCategory): boolean {
  return TW_SCAM_KEYWORDS[category].some((keyword) => text.includes(keyword));
}

export function getMatchedKeywords(text: string, category: TwScamKeywordCategory): string[] {
  return TW_SCAM_KEYWORDS[category].filter((keyword) => text.includes(keyword));
}
