/**
 * Generalization Test Suite
 *
 * Tests the analysis pipeline against:
 *   1. Diverse scam attack variants (including edge cases the keyword list may miss)
 *   2. Hard-negative legit messages (false-positive stress test)
 *
 * Run: npm run test:generalization
 *
 * Outputs:
 *   data/processed/generalization-report.json
 *   data/processed/generalization-report.md
 *
 * Gap probes are marked gapTest: true — they are expected to be harder and a lower
 * detection rate there is a signal for where the model needs improvement, not a failure.
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "data", "processed");
const JSON_REPORT_PATH = path.join(OUTPUT_DIR, "generalization-report.json");
const MD_REPORT_PATH = path.join(OUTPUT_DIR, "generalization-report.md");

// A scam probe passes if score >= this threshold (warn/block range).
const SCAM_DETECTION_THRESHOLD = 40;
// A legit probe passes (no false positive) if score <= this threshold.
const LEGIT_SAFE_THRESHOLD = 35;

// ─────────────────────────────────────────────
// PROBE SUITE
// Each probe = one attack scenario.
// Each variant = one concrete sample input.
// ─────────────────────────────────────────────

const PROBE_SUITE = [

  // ── 1. Bank credential-harvest email ──────────────────────────────────────
  {
    id: "ph_bank_email",
    name: "Bank phishing email (brand impersonation + sender mismatch)",
    attackType: "credential_harvest",
    channel: "email",
    language: "zh",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_bank_email_esun",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/msg001",
          hostname: "mail.google.com",
          source: "email",
          title: "玉山銀行帳戶異常通知",
          visibleText: "您的玉山銀行帳戶出現異常登入，請立即點擊連結驗證身分，否則帳戶將在24小時後停用。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 2,
            mismatchedTextCount: 1,
            suspiciousTldCount: 0,
            hostnames: ["secure-esun-verify.click"],
            urls: ["https://secure-esun-verify.click/auth"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["玉山"],
          email: {
            provider: "gmail",
            subject: "【玉山銀行】帳戶異常警告 - 請立即處理",
            sender: "service@esun-secure-alert.com",
            replyTo: "noreply@gmail.com",
            bodyText: "親愛的玉山銀行客戶您好，我們偵測到您的帳戶出現異常登入，請立即點擊下方連結驗證您的身分，否則帳戶將在24小時後暫停使用。",
            linkCount: 2
          }
        }
      },
      {
        id: "ph_bank_email_ctbc",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/msg002",
          hostname: "mail.google.com",
          source: "email",
          title: "中國信託帳戶安全通知",
          visibleText: "您的中國信託網路銀行密碼即將到期，請點擊以下連結重設密碼，確保帳戶安全。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 2,
            mismatchedTextCount: 1,
            suspiciousTldCount: 0,
            hostnames: ["ctbc-secure.top"],
            urls: ["https://ctbc-secure.top/reset"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["中國信託", "中信"],
          email: {
            provider: "gmail",
            subject: "【中國信託】密碼安全提醒",
            sender: "security@ctbc-alert.net",
            replyTo: "no-reply@hotmail.com",
            bodyText: "您的中國信託網路銀行密碼即將到期，請點擊以下連結重設密碼以確保帳戶安全，逾期將無法使用網路銀行服務。",
            linkCount: 2
          }
        }
      },
      {
        id: "ph_bank_email_fubon",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/msg003",
          hostname: "mail.google.com",
          source: "email",
          title: "台北富邦銀行安全驗證",
          visibleText: "偵測到異常交易，請立即驗證身分以保護您的富邦帳戶資金安全。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 1,
            mismatchedTextCount: 1,
            suspiciousTldCount: 0,
            hostnames: ["fubon-security-check.com"],
            urls: ["https://fubon-security-check.com/verify"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["富邦"],
          email: {
            provider: "gmail",
            subject: "富邦銀行：異常交易偵測，需立即驗證",
            sender: "alert@fubon-protect.xyz",
            replyTo: "noreply@yahoo.com",
            bodyText: "尊敬的客戶，我們偵測到您的帳戶有一筆可疑交易，為保護您的資金安全請立即驗證身分，否則我們將暫停您的帳戶。",
            linkCount: 1
          }
        }
      }
    ]
  },

  // ── 2. Fake logistics SMS ─────────────────────────────────────────────────
  {
    id: "ph_logistics_sms",
    name: "Fake logistics SMS (假物流短訊)",
    attackType: "payment_fraud",
    channel: "sms",
    language: "zh",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_logistics_sms_blackcat",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "【黑貓宅配】您的包裹(#TW20240301)因地址不符無法投遞，請於24小時內至 https://bit.ly/3xRk9zQ 更新資料，逾時將退回。",
          claimedBrand: "黑貓宅配"
        }
      },
      {
        id: "ph_logistics_sms_post",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "【台灣郵局】您有一件包裹因清關費用未付，需繳清關稅NT$98元，請點擊繳費：https://reurl.cc/fake99",
          claimedBrand: "台灣郵局"
        }
      },
      {
        id: "ph_logistics_sms_hct",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "【新竹物流】配送失敗通知：您的宅配包裹無法送達，請立即至以下連結確認您的收件資料，否則包裹將退回。http://lihi.cc/xYzAb",
          claimedBrand: "新竹物流"
        }
      }
    ]
  },

  // ── 3. Fake logistics – paraphrase gap test ───────────────────────────────
  {
    id: "ph_logistics_paraphrase",
    name: "Fake logistics with paraphrased keywords (換詞規避關鍵字 ← gap test)",
    attackType: "payment_fraud",
    channel: "sms",
    language: "zh",
    expectScam: true,
    gapTest: true,
    notes: "Uses synonyms that are NOT in TW_SCAM_KEYWORDS. Tests keyword-level generalization.",
    variants: [
      {
        id: "ph_logistics_paraphrase_1",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "您好，您的快遞因收件人資訊有誤，目前暫存於轉運中心，需要您更新寄送地址，請盡快處理以避免退件：https://bit.ly/update99",
          claimedBrand: "快遞"
        }
      },
      {
        id: "ph_logistics_paraphrase_2",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "通知：您有一件海外商品等待通關，需支付少量行政費用方可放行，請至以下網址辦理：http://tw-customs-clearance.xyz/pay",
          claimedBrand: ""
        }
      }
    ]
  },

  // ── 4. Investment scam (LINE group) ───────────────────────────────────────
  {
    id: "ph_investment_line",
    name: "LINE investment group scam (股票/加密投資群)",
    attackType: "investment_scam",
    channel: "line",
    language: "zh",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_investment_line_1",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "老師今天帶單又獲利了！保證獲利的投資群還有名額，有興趣的加入我們的飆股討論群組，入金就可以開始跟單！",
          claimedBrand: ""
        }
      },
      {
        id: "ph_investment_line_2",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "【限時招募】加密貨幣穩賺不賠的套利方案，出金自由，有興趣私訊我，老師親自帶單，投顧團隊親自操盤。",
          claimedBrand: ""
        }
      },
      {
        id: "ph_investment_line_3",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "🔥 虛擬貨幣入金立享20%獎勵，限前50名！投資群開放申請，每日報酬穩定3~5%，帶單老師實力見證，現在加入還來得及！",
          claimedBrand: ""
        }
      }
    ]
  },

  // ── 5. Investment scam – new terminology gap test ─────────────────────────
  {
    id: "ph_investment_newterms",
    name: "Investment scam with emerging terminology (新型話術 ← gap test)",
    attackType: "investment_scam",
    channel: "line",
    language: "mixed",
    expectScam: true,
    gapTest: true,
    notes: "Uses 'AI量化', 'Web3套利', 'DeFi' — not in TW_SCAM_KEYWORDS investment list.",
    variants: [
      {
        id: "ph_investment_newterms_ai",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "我們的AI量化交易系統每日自動套利，過去半年平均月收益18%，現在開放新用戶試用，只需少量資金即可開始體驗！",
          claimedBrand: ""
        }
      },
      {
        id: "ph_investment_newterms_web3",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "Web3 DeFi流動性挖礦計畫，年化收益超過200%，我們的分析師團隊精選標的，讓您的資金穩定成長，私訊了解詳情。",
          claimedBrand: ""
        }
      },
      {
        id: "ph_investment_newterms_arbitrage",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "專業套利機器人，24小時監控市場價差，回測年化報酬率350%，只要把資金交給我們的智能系統，每月固定配息。",
          claimedBrand: ""
        }
      }
    ]
  },

  // ── 6. Government impersonation SMS ──────────────────────────────────────
  {
    id: "ph_government_sms",
    name: "Fake government notice (假政府機關簡訊)",
    attackType: "government_impersonation",
    channel: "sms",
    language: "zh",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_govt_tax",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "【國稅局】您有一筆漏報稅款NT$4,200，逾期將加計罰款，請至以下連結補繳：https://tax-gov-tw.click/pay，逾期視同蓄意逃漏稅。",
          claimedBrand: "國稅局"
        }
      },
      {
        id: "ph_govt_traffic",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "【交通部監理站】您有一張違規罰單尚未繳納，已逾期30天，請即時至 https://reurl.cc/faketicket 繳清，否則將移送地檢署追訴。",
          claimedBrand: "監理站"
        }
      },
      {
        id: "ph_govt_health",
        kind: "text",
        input: {
          source: "text",
          channel: "sms",
          text: "【健保署】您的健保費用有異常繳款紀錄，需至以下連結確認，否則健保資格將暫停：https://bit.ly/nhisupdate",
          claimedBrand: "健保署"
        }
      }
    ]
  },

  // ── 7. Customer service scam (假客服解除分期) ────────────────────────────
  {
    id: "ph_customer_service",
    name: "Fake customer service / installment scam (假客服 + 解除分期)",
    attackType: "customer_service_scam",
    channel: "phone_transcript",
    language: "zh",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_cs_shopee",
        kind: "text",
        input: {
          source: "text",
          channel: "phone_transcript",
          text: "您好，我是蝦皮客服，您的帳戶被誤設了每月自動扣款分期付款，需要您前往ATM操作解除分期，請不要掛電話，我會一步一步指導您操作。",
          claimedBrand: "蝦皮"
        }
      },
      {
        id: "ph_cs_momo",
        kind: "text",
        input: {
          source: "text",
          channel: "phone_transcript",
          text: "您好這裡是momo購物客服中心，您的訂單異常，被系統重複扣款，我們需要協助您解除分期，請照我說的去操作ATM或是轉帳，驗證碼會傳給您。",
          claimedBrand: "momo"
        }
      }
    ]
  },

  // ── 8. Account takeover email threat ─────────────────────────────────────
  {
    id: "ph_account_takeover",
    name: "Account-takeover email (帳號停用威脅 + 短連結)",
    attackType: "credential_harvest",
    channel: "email",
    language: "mixed",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_ato_gmail_style",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/ato001",
          hostname: "mail.google.com",
          source: "email",
          title: "Your account will be disabled",
          visibleText: "Your mailbox storage is full and incoming emails are being blocked. Verify your account immediately to restore service.",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 1,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["bit.ly"],
            urls: ["https://bit.ly/verify-mailbox-now"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: [],
          email: {
            provider: "gmail",
            subject: "Action Required: Your mailbox will be disabled in 24 hours",
            sender: "admin@mail-security-notice.net",
            replyTo: "no-reply@gmail-support.org",
            bodyText: "Your mailbox is almost full and incoming mails are being blocked. Click the link below to verify your account immediately. Failure to verify will result in account deletion.",
            linkCount: 1
          }
        }
      },
      {
        id: "ph_ato_zh_style",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/ato002",
          hostname: "mail.google.com",
          source: "email",
          title: "您的信箱即將停用",
          visibleText: "您的信箱空間已滿，收件功能即將停用。請立即點擊連結驗證身分以恢復服務。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 1,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["reurl.cc"],
            urls: ["https://reurl.cc/mailbox-verify"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: [],
          email: {
            provider: "gmail",
            subject: "緊急通知：您的信箱即將因空間不足停用",
            sender: "webmaster@mail-support-tw.com",
            replyTo: "noreply@yahoo.com.tw",
            bodyText: "您的信箱儲存空間已達上限，收件功能即將停用。請立即點擊以下連結驗證並清理信箱，否則您的帳號將於24小時後刪除。",
            linkCount: 1
          }
        }
      }
    ]
  },

  // ── 9. Romance scam ───────────────────────────────────────────────────────
  {
    id: "ph_romance",
    name: "Romance scam – money transfer request",
    attackType: "payment_fraud",
    channel: "line",
    language: "zh",
    expectScam: true,
    gapTest: false,
    variants: [
      {
        id: "ph_romance_transfer",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "寶貝我現在在海外有急事，銀行帳戶被凍結了，你可以先幫我匯NT$30000嗎？等我回國就還你，拜託了。",
          claimedBrand: ""
        }
      },
      {
        id: "ph_romance_investment",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "我一直在幫你想，你現在的薪水根本不夠用，我介紹你一個很好賺的平台，只要入金就可以開始獲利，我們一起存錢以後見面。",
          claimedBrand: ""
        }
      }
    ]
  },

  // ── 10. English-only phishing (English to TW users ← gap test) ────────────
  {
    id: "ph_english_only",
    name: "English-language phishing (全英文釣魚 ← gap test)",
    attackType: "credential_harvest",
    channel: "email",
    language: "en",
    expectScam: true,
    gapTest: true,
    notes: "Pure English scam targeting TW users. TW keyword list won't fire. Tests English-path coverage.",
    variants: [
      {
        id: "ph_english_paypal",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/en001",
          hostname: "mail.google.com",
          source: "email",
          title: "Your PayPal account has been limited",
          visibleText: "Your PayPal account access has been temporarily limited. Please verify your account to restore full access.",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 1,
            mismatchedTextCount: 1,
            suspiciousTldCount: 0,
            hostnames: ["paypal-secure-verify.com"],
            urls: ["https://paypal-secure-verify.com/confirm"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["paypal"],
          email: {
            provider: "gmail",
            subject: "Your PayPal account has been limited",
            sender: "service@paypal-notifications.net",
            replyTo: "no-reply@hotmail.com",
            bodyText: "Your PayPal account access has been temporarily limited due to suspicious activity. Please click the link below to verify your identity and restore full access to your account.",
            linkCount: 1
          }
        }
      },
      {
        id: "ph_english_apple",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/en002",
          hostname: "mail.google.com",
          source: "email",
          title: "Apple ID Sign-In Attempt",
          visibleText: "Someone tried to sign in to your Apple ID. Verify your identity immediately to secure your account.",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 1,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["apple-id-secure.support"],
            urls: ["https://apple-id-secure.support/verify"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["apple"],
          email: {
            provider: "gmail",
            subject: "Important: Apple ID Sign-In Attempt From Unknown Device",
            sender: "security@apple-id-support.net",
            replyTo: "noreply@gmail.com",
            bodyText: "We detected a sign-in attempt on your Apple ID from an unknown device. If this wasn't you, click below to secure your account immediately.",
            linkCount: 1
          }
        }
      }
    ]
  },

  // ── 11. Warm-up / first-contact message (gap test) ────────────────────────
  {
    id: "ph_warmup",
    name: "Warm-up / first-contact scam (無明顯詐騙請求 ← gap test)",
    attackType: "unknown",
    channel: "line",
    language: "zh",
    expectScam: false,  // Not expected to score high — this IS the gap by design
    gapTest: true,
    notes: "First-contact messages before any scam ask. Low score is expected and correct. Documents the gap.",
    variants: [
      {
        id: "ph_warmup_1",
        kind: "text",
        input: {
          source: "text",
          channel: "line",
          text: "你好，我是陳小姐，偶然在社群看到你的帳號覺得很有緣，可以加個好友嗎？我平常有在做一些副業想找志同道合的人聊聊。",
          claimedBrand: ""
        }
      }
    ]
  },

  // ══════════════════════════════════════════════
  // LEGIT PROBES (false-positive stress tests)
  // ══════════════════════════════════════════════

  // ── L1. Legit bank transaction notification ───────────────────────────────
  {
    id: "legit_bank_notification",
    name: "Legit bank transaction notification (正常銀行交易通知)",
    attackType: "unknown",
    channel: "email",
    language: "zh",
    expectScam: false,
    gapTest: false,
    variants: [
      {
        id: "legit_bank_esun_txn",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/legit001",
          hostname: "mail.google.com",
          source: "email",
          title: "玉山銀行消費通知",
          visibleText: "您於7-11消費NT$85，帳戶餘額NT$42,300，如有疑問請撥客服專線。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 2,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["www.esunbank.com.tw", "esunbank.com.tw"],
            urls: ["https://www.esunbank.com.tw/bank/personal", "https://www.esunbank.com.tw/contact"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["玉山"],
          email: {
            provider: "gmail",
            subject: "玉山銀行消費通知 - 7-11 NT$85",
            sender: "notification@esunbank.com.tw",
            replyTo: "notification@esunbank.com.tw",
            bodyText: "您好，您的玉山信用卡剛完成一筆消費：商店 統一超商7-11，金額 NT$85，消費時間 2024/03/15 14:32。如有疑問請洽客服專線 0800-888-888。",
            linkCount: 2
          }
        }
      }
    ]
  },

  // ── L2. Legit logistics tracking email ───────────────────────────────────
  {
    id: "legit_logistics_tracking",
    name: "Legit logistics tracking notification (正常物流追蹤通知)",
    attackType: "unknown",
    channel: "email",
    language: "zh",
    expectScam: false,
    gapTest: false,
    variants: [
      {
        id: "legit_logistics_hct_ok",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/legit002",
          hostname: "mail.google.com",
          source: "email",
          title: "新竹物流配送通知",
          visibleText: "您的包裹已於今日下午送達，取件編號 TW2024031500012，感謝您使用新竹物流。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 2,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["www.hct.com.tw"],
            urls: ["https://www.hct.com.tw/tracking", "https://www.hct.com.tw/"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["新竹物流"],
          email: {
            provider: "gmail",
            subject: "【新竹物流】您的包裹已送達",
            sender: "service@hct.com.tw",
            replyTo: "service@hct.com.tw",
            bodyText: "您好，您的包裹已成功送達，取件單號：TW2024031500012，如有問題請洽客服。感謝您使用新竹物流服務。",
            linkCount: 2
          }
        }
      }
    ]
  },

  // ── L3. Legit IT password reset ───────────────────────────────────────────
  {
    id: "legit_it_password_reset",
    name: "Legit IT department password reset (正常IT密碼重設通知)",
    attackType: "unknown",
    channel: "email",
    language: "zh",
    expectScam: false,
    gapTest: false,
    variants: [
      {
        id: "legit_it_reset_1",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/legit003",
          hostname: "mail.google.com",
          source: "email",
          title: "IT部門：系統密碼將於7天後到期",
          visibleText: "您的公司系統密碼將於7天後到期，請登入內部系統更新密碼，如有問題請聯絡IT部門。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 2,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["internal.company.com.tw"],
            urls: ["https://internal.company.com.tw/password", "https://internal.company.com.tw/help"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: [],
          email: {
            provider: "outlook",
            subject: "【IT通知】您的帳號密碼將於7天後到期",
            sender: "it-helpdesk@company.com.tw",
            replyTo: "it-helpdesk@company.com.tw",
            bodyText: "親愛的同仁，您的公司帳號密碼將於7天後到期，請於到期前登入人事系統更新密碼，以避免帳號遭到鎖定。如有問題，請洽分機 1234 或 IT 服務台。謝謝。",
            linkCount: 2
          }
        }
      }
    ]
  },

  // ── L4. Legit e-commerce order confirmation ───────────────────────────────
  {
    id: "legit_ecommerce_order",
    name: "Legit e-commerce order confirmation (正常電商訂單確認)",
    attackType: "unknown",
    channel: "email",
    language: "zh",
    expectScam: false,
    gapTest: false,
    variants: [
      {
        id: "legit_shopee_order",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/legit004",
          hostname: "mail.google.com",
          source: "email",
          title: "蝦皮購物 - 訂單確認",
          visibleText: "您的訂單已成功下單，訂單編號 24031500001，預計3-5工作天到貨，感謝您在蝦皮購物。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 3,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["shopee.tw", "help.shopee.tw"],
            urls: ["https://shopee.tw/user/purchase/order/24031500001", "https://help.shopee.tw/"]
          },
          dom: { hiddenElementCount: 0, iframeCount: 0 },
          brandSignals: ["蝦皮"],
          email: {
            provider: "gmail",
            subject: "蝦皮購物：訂單 #24031500001 已確認",
            sender: "noreply@mail.shopee.tw",
            replyTo: "noreply@mail.shopee.tw",
            bodyText: "感謝您的購買！您的訂單 #24031500001 已成功成立，商品預計 3-5 個工作天到達，您可以至訂單查詢頁面追蹤物流狀態。",
            linkCount: 3
          }
        }
      }
    ]
  },

  // ── L5. Legit newsletter with urgency-like content ────────────────────────
  {
    id: "legit_newsletter_urgency",
    name: "Legit newsletter with urgency language (含限時優惠正常電子報 ← false-positive risk)",
    attackType: "unknown",
    channel: "email",
    language: "zh",
    expectScam: false,
    gapTest: false,
    variants: [
      {
        id: "legit_newsletter_sale",
        kind: "page",
        features: {
          url: "https://mail.google.com/mail/u/0/#inbox/legit005",
          hostname: "mail.google.com",
          source: "email",
          title: "momo購物 週年慶限時優惠",
          visibleText: "週年慶限時三天！全館滿千折百，付款方式包含信用卡分期0利率，趕快把握機會下單。",
          forms: { total: 0, passwordFields: 0, externalSubmitCount: 0 },
          links: {
            total: 8,
            mismatchedTextCount: 0,
            suspiciousTldCount: 0,
            hostnames: ["www.momoshop.com.tw", "m.momoshop.com.tw"],
            urls: [
              "https://www.momoshop.com.tw/main/Main.jsp",
              "https://www.momoshop.com.tw/category/DgrpCategory.jsp",
              "https://m.momoshop.com.tw/",
              "https://www.momoshop.com.tw/rule/privacyPolicy.jsp"
            ]
          },
          dom: { hiddenElementCount: 2, iframeCount: 0 },
          brandSignals: ["momo"],
          email: {
            provider: "gmail",
            subject: "momo購物週年慶 🎉 限時3天，全館滿千折百！",
            sender: "edm@momoshop.com.tw",
            replyTo: "edm@momoshop.com.tw",
            bodyText: "momo購物週年慶正式開跑！限時三天全館優惠，信用卡分期0利率付款，千萬不要錯過！立即前往momo選購您心儀的商品。如不想收到此類郵件，請點擊取消訂閱。",
            linkCount: 8
          }
        }
      }
    ]
  }
];

// ─────────────────────────────────────────────
// RUNNER
// ─────────────────────────────────────────────

function detectLanguage(text) {
  const hasHan = /[\p{Script=Han}]/u.test(text);
  const hasLatin = /[A-Za-z]/.test(text);
  if (hasHan && hasLatin) return "mixed";
  if (hasHan) return "zh";
  if (hasLatin) return "en";
  return "unknown";
}

async function runProbe(probe, analyzeFeatures, analyzeText) {
  const results = [];

  for (const variant of probe.variants) {
    let analysis;

    try {
      if (variant.kind === "text") {
        analysis = await analyzeText(variant.input);
      } else {
        analysis = await analyzeFeatures(variant.features);
      }
    } catch (error) {
      analysis = {
        score: 0,
        riskLevel: "low",
        recommendedAction: "allow",
        attackType: "unknown",
        reasons: [`Analysis error: ${error.message}`],
        provider: "error"
      };
    }

    const isDetected = probe.expectScam
      ? analysis.score >= SCAM_DETECTION_THRESHOLD
      : analysis.score <= LEGIT_SAFE_THRESHOLD;

    results.push({
      probeId: probe.id,
      variantId: variant.id,
      probeName: probe.name,
      attackType: probe.attackType,
      channel: probe.channel,
      language: probe.language,
      expectScam: probe.expectScam,
      gapTest: probe.gapTest,
      notes: probe.notes,
      score: analysis.score,
      riskLevel: analysis.riskLevel,
      action: analysis.recommendedAction,
      detectedCorrectly: isDetected,
      reasons: (analysis.reasons ?? []).slice(0, 4)
    });
  }

  return results;
}

function summarizeByField(results, field) {
  const map = {};
  for (const r of results) {
    const key = r[field] ?? "unknown";
    if (!map[key]) map[key] = { total: 0, passed: 0 };
    map[key].total += 1;
    if (r.detectedCorrectly) map[key].passed += 1;
  }
  for (const key of Object.keys(map)) {
    map[key].passRate = Number(((map[key].passed / map[key].total) * 100).toFixed(1));
  }
  return map;
}

function buildCoverageGaps(results) {
  const byAttackType = summarizeByField(
    results.filter((r) => r.expectScam && !r.gapTest),
    "attackType"
  );

  const gaps = [];
  for (const [attackType, stats] of Object.entries(byAttackType)) {
    if (stats.passRate < 70) {
      gaps.push({ attackType, ...stats });
    }
  }

  return gaps.sort((a, b) => a.passRate - b.passRate);
}

function toMarkdown(report) {
  const missedScam = report.allResults.filter((r) => r.expectScam && !r.gapTest && !r.detectedCorrectly);
  const falsePositives = report.allResults.filter((r) => !r.expectScam && !r.detectedCorrectly);
  const gapResults = report.allResults.filter((r) => r.gapTest);

  return `# Generalization Test Report

Generated: ${report.generatedAt}
Thresholds: scam detection ≥ ${SCAM_DETECTION_THRESHOLD} | legit safe ≤ ${LEGIT_SAFE_THRESHOLD}

---

## Overall

| Metric | Value |
|--------|-------|
| Core scam detection rate | **${report.summary.coreScam.passRate}%** (${report.summary.coreScam.passed}/${report.summary.coreScam.total}) |
| Legit false-positive rate | **${report.summary.legit.fpRate}%** (${report.summary.legit.falsePosCount}/${report.summary.legit.total}) |
| Gap probe detection rate | ${report.summary.gapTests.passRate}% (${report.summary.gapTests.passed}/${report.summary.gapTests.total}) |

---

## By Attack Type (core probes only)

\`\`\`json
${JSON.stringify(report.byAttackType, null, 2)}
\`\`\`

## By Channel

\`\`\`json
${JSON.stringify(report.byChannel, null, 2)}
\`\`\`

## By Language

\`\`\`json
${JSON.stringify(report.byLanguage, null, 2)}
\`\`\`

---

## Coverage Gaps (core scam probes < 70% detection)

${report.coverageGaps.length === 0
  ? "No coverage gaps detected in core probes."
  : report.coverageGaps.map((g) => `- **${g.attackType}**: ${g.passRate}% (${g.passed}/${g.total})`).join("\n")}

---

## Missed Core Scam Cases

${missedScam.length === 0
  ? "All core scam probes detected."
  : missedScam.map((r) =>
    `### ${r.variantId} (${r.attackType} / ${r.channel})
- Score: ${r.score} — Action: ${r.action}
- Reasons: ${r.reasons.join("; ") || "none"}`
  ).join("\n\n")}

---

## False Positives (legit incorrectly flagged)

${falsePositives.length === 0
  ? "No false positives."
  : falsePositives.map((r) =>
    `### ${r.variantId}
- Score: ${r.score} — Action: ${r.action}
- Reasons: ${r.reasons.join("; ") || "none"}`
  ).join("\n\n")}

---

## Gap Probe Results

These probes test known blind spots. A low detection rate here indicates a real gap in coverage.

${gapResults.map((r) =>
  `- **${r.variantId}** [${r.attackType}] score=${r.score} detected=${r.detectedCorrectly}
  Notes: ${r.notes ?? "—"}`
).join("\n")}
`;
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

async function main() {
  const [{ analyzeFeatures }, { analyzeText }] = await Promise.all([
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/analyze.js")).href),
    import(pathToFileURL(path.join(ROOT, "apps/api/dist/pipeline/text-analyzer.js")).href)
  ]);

  console.log(`Running ${PROBE_SUITE.length} probes...`);

  const allResults = [];
  for (const probe of PROBE_SUITE) {
    const results = await runProbe(probe, analyzeFeatures, analyzeText);
    allResults.push(...results);
    const passed = results.filter((r) => r.detectedCorrectly).length;
    const flag = probe.gapTest ? " [gap]" : "";
    console.log(`  ${probe.id}${flag}: ${passed}/${results.length} correct`);
  }

  const coreScam = allResults.filter((r) => r.expectScam && !r.gapTest);
  const legit = allResults.filter((r) => !r.expectScam && !r.gapTest);
  const gapTests = allResults.filter((r) => r.gapTest);

  const coreScamPassed = coreScam.filter((r) => r.detectedCorrectly).length;
  const legitPassed = legit.filter((r) => r.detectedCorrectly).length;
  const gapPassed = gapTests.filter((r) => r.detectedCorrectly).length;

  const report = {
    generatedAt: new Date().toISOString(),
    thresholds: { scamDetection: SCAM_DETECTION_THRESHOLD, legitSafe: LEGIT_SAFE_THRESHOLD },
    summary: {
      coreScam: {
        total: coreScam.length,
        passed: coreScamPassed,
        passRate: Number(((coreScamPassed / Math.max(coreScam.length, 1)) * 100).toFixed(1))
      },
      legit: {
        total: legit.length,
        passed: legitPassed,
        falsePosCount: legit.length - legitPassed,
        fpRate: Number((((legit.length - legitPassed) / Math.max(legit.length, 1)) * 100).toFixed(1))
      },
      gapTests: {
        total: gapTests.length,
        passed: gapPassed,
        passRate: Number(((gapPassed / Math.max(gapTests.length, 1)) * 100).toFixed(1))
      }
    },
    coverageGaps: buildCoverageGaps(allResults),
    byAttackType: summarizeByField(allResults.filter((r) => r.expectScam && !r.gapTest), "attackType"),
    byChannel: summarizeByField(allResults.filter((r) => !r.gapTest), "channel"),
    byLanguage: summarizeByField(allResults.filter((r) => !r.gapTest), "language"),
    allResults
  };

  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(JSON_REPORT_PATH, JSON.stringify(report, null, 2));
  await writeFile(MD_REPORT_PATH, toMarkdown(report));

  console.log("\n" + "─".repeat(50));
  console.log(`Core scam detection:  ${report.summary.coreScam.passRate}% (${coreScamPassed}/${coreScam.length})`);
  console.log(`Legit false-positive: ${report.summary.legit.fpRate}% (${report.summary.legit.falsePosCount}/${legit.length})`);
  console.log(`Gap probe detection:  ${report.summary.gapTests.passRate}% (${gapPassed}/${gapTests.length})`);

  if (report.coverageGaps.length > 0) {
    console.log("\nCoverage gaps (< 70% detection):");
    for (const gap of report.coverageGaps) {
      console.log(`  ⚠ ${gap.attackType}: ${gap.passRate}%`);
    }
  }

  console.log(`\nReports: ${JSON_REPORT_PATH}`);
  console.log(`         ${MD_REPORT_PATH}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
