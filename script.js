const scenarios = [
  {
    from: "Microsoft 365 Support <security-alert@micros0ft-portal-update.com>",
    subject: "Action Required: Password Expired For organization.com",
    body: `
      <p>Hello Team Member,</p>
      <p>Your institutional enterprise password has reached its maximum security threshold and will expire in <strong>2 hours</strong>.</p>
      <p>Failure to update your profile immediately will revoke all active directory privileges, email synchronization, and cloud storage access.</p>
      <p style="margin: 1.5rem 0;">
        <a href="#" class="preview-link" data-url="http://auth-micros0ft.login-verify.com/reset">Keep Current Password & Re-verify Now &rarr;</a>
      </p>
      <p>IT Infrastructure Operations Desk</p>
    `,
    isPhish: true,
    reasons: [
      "The sender domain micros0ft-portal-update.com uses typosquatting (0 substituted for o).",
      "The link points to login-verify.com rather than microsoftonline.com or your employer's tenant.",
      "The email relies on an artificial 2-hour deadline to create urgency and panic."
    ]
  },
  {
    from: "Human Resources <hr-notices@internal-payroll.net>",
    subject: "Q3 Incentive Structure & Direct Deposit Verification",
    body: `
      <p>All Staff,</p>
      <p>Attached is the updated discretionary bonus compensation table for the current quarter.</p>
      <p>To qualify for this payroll processing cycle, authenticate your current direct deposit account number via the secure link below.</p>
      <p style="margin: 1.5rem 0;">
        <a href="#" class="preview-link" data-url="http://194.26.29.112/payroll-update/auth">Access Direct Deposit Portal &rarr;</a>
      </p>
      <p>Human Resources Operations</p>
    `,
    isPhish: true,
    reasons: [
      "The hyperlink directs to a raw numerical IP address (194.26.29.112) instead of a certified company domain.",
      "Legitimate HR teams do not request complete direct deposit account numbers via unauthenticated external links.",
      "The sender domain internal-payroll.net is a lookalike domain unassociated with internal corporate infrastructure."
    ]
  },
  {
    from: "Corporate IT Support <servicedesk@company.com>",
    subject: "Scheduled Maintenance: VPN Server Updates Sunday 02:00 UTC",
    body: `
      <p>Good afternoon,</p>
      <p>Routine network maintenance on the primary VPN gateways is scheduled for Sunday from 02:00 to 04:00 UTC.</p>
      <p>No action is required on your part. If you experience disconnection issues following the window, review the internal documentation on the company wiki or submit a ticket through the regular portal.</p>
      <p style="margin: 1.5rem 0;">
        <a href="#" class="preview-link" data-url="https://wiki.company.com/it/maintenance-schedule">View VPN Server Maintenance Windows &rarr;</a>
      </p>
      <p>Internal IT Service Desk</p>
    `,
    isPhish: false,
    reasons: [
      "The sender address matches the official company domain (company.com).",
      "The message states no action is required and does not ask for credentials or financial details.",
      "The destination URL points to the legitimate internal company subdomain (wiki.company.com)."
    ]
  }
];

let activeScenarioIndex = 0;

const simFrom = document.getElementById("sim-from");
const simSubject = document.getElementById("sim-subject");
const simBody = document.getElementById("sim-body");
const simFeedback = document.getElementById("sim-feedback");
const feedbackBadge = document.getElementById("feedback-badge");
const feedbackMessage = document.getElementById("feedback-message");
const feedbackReasons = document.getElementById("feedback-reasons");
const simActions = document.getElementById("sim-actions");
const hoverPreview = document.getElementById("hover-preview");
const hoverUrl = document.getElementById("hover-url");

function loadScenario(index) {
  activeScenarioIndex = index;
  const current = scenarios[index];

  simFrom.textContent = current.from;
  simSubject.textContent = current.subject;
  simBody.innerHTML = current.body;

  simFeedback.className = "sim-feedback hidden";
  simActions.classList.remove("hidden");
  hoverPreview.classList.remove("visible");

  const previewLinks = simBody.querySelectorAll(".preview-link");
  previewLinks.forEach((link) => {
    link.addEventListener("mouseenter", (e) => {
      e.preventDefault();
      hoverUrl.textContent = link.getAttribute("data-url");
      hoverPreview.classList.add("visible");
    });
    link.addEventListener("mouseleave", () => {
      hoverPreview.classList.remove("visible");
    });
    link.addEventListener("click", (e) => {
      e.preventDefault();
    });
  });
}

document.querySelectorAll(".sim-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".sim-tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    loadScenario(parseInt(tab.getAttribute("data-scenario"), 10));
  });
});

function handleVerdict(userSaidPhish) {
  const current = scenarios[activeScenarioIndex];
  const isCorrect = userSaidPhish === current.isPhish;

  simFeedback.className = "sim-feedback " + (isCorrect ? "correct" : "incorrect");
  feedbackBadge.textContent = isCorrect ? "Correct Identification" : "Incorrect Assessment";
  feedbackMessage.textContent = isCorrect
    ? "Good catch. Your evaluation matches the threat profile."
    : "Review the red flags present in this communication.";

  feedbackReasons.innerHTML = "";
  current.reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    feedbackReasons.appendChild(li);
  });

  simActions.classList.add("hidden");
}

document.getElementById("btn-report-phish").addEventListener("click", () => handleVerdict(true));
document.getElementById("btn-mark-legit").addEventListener("click", () => handleVerdict(false));

const urlInput = document.getElementById("url-input");
const btnAnalyze = document.getElementById("btn-analyze-url");
const partProtocol = document.getElementById("part-protocol");
const partSubdomain = document.getElementById("part-subdomain");
const partDomain = document.getElementById("part-domain");
const partPath = document.getElementById("part-path");
const urlVerdict = document.getElementById("url-verdict");

function analyzeUrl(rawUrl) {
  try {
    let normalized = rawUrl.trim();
    if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
      normalized = "https://" + normalized;
    }

    const parsed = new URL(normalized);
    const hostParts = parsed.hostname.split(".");

    let domain = "";
    let subdomain = "";

    if (hostParts.length > 2) {
      domain = hostParts.slice(-2).join(".");
      subdomain = hostParts.slice(0, -2).join(".");
    } else {
      domain = parsed.hostname;
      subdomain = "(none)";
    }

    partProtocol.textContent = parsed.protocol + "//";
    partSubdomain.textContent = subdomain;
    partDomain.textContent = domain;
    partPath.textContent = parsed.pathname || "/";

    if (parsed.hostname.includes("login-verify") || parsed.hostname.includes("user-verify") || parsed.hostname.includes("micros0ft")) {
      urlVerdict.style.color = "#f87171";
      urlVerdict.textContent = "High Risk: The real domain does not belong to the brand being displayed in the subdomain prefix.";
    } else if (parsed.hostname.endsWith("google.com") || parsed.hostname.endsWith("microsoftonline.com")) {
      urlVerdict.style.color = "#34d399";
      urlVerdict.textContent = "Legitimate: The root domain is authentic and securely registered.";
    } else {
      urlVerdict.style.color = "#fbbf24";
      urlVerdict.textContent = "Caution: Confirm the domain owner before entering credentials or executing file downloads.";
    }
  } catch (err) {
    urlVerdict.style.color = "#f87171";
    urlVerdict.textContent = "Invalid URL syntax. Please enter a valid web address.";
  }
}

btnAnalyze.addEventListener("click", () => analyzeUrl(urlInput.value));

document.querySelectorAll(".btn-chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    const sample = btn.getAttribute("data-sample");
    urlInput.value = sample;
    analyzeUrl(sample);
  });
});

const quizData = [
  {
    q: "You receive an email from the IT Desk stating your mailbox is full and you must verify credentials in 1 hour. What is your first step?",
    options: [
      "Click the link immediately to prevent email loss.",
      "Reply with your current password so they can expand storage.",
      "Check the actual sender address and contact the IT team through a known internal channel.",
      "Forward the email to all colleagues to ask if they received it."
    ],
    answer: 2
  },
  {
    q: "Which of the following domains is genuinely owned by Microsoft?",
    options: [
      "login.microsoftonline.com.attacker-controlled.net",
      "login.microsoftonline.com",
      "www.micros0ft-support.com",
      "update-microsoft-account.com"
    ],
    answer: 1
  },
  {
    q: "What is the primary objective of a Business Email Compromise (Whaling/BEC) attack?",
    options: [
      "Disrupt network routers using DDoS techniques.",
      "Manipulate finance personnel into executing fraudulent funds transfers or sharing sensitive data.",
      "Deface public websites with political slogans.",
      "Infect gaming consoles on home networks."
    ],
    answer: 1
  },
  {
    q: "Why is Multi-Factor Authentication (MFA) considered an essential defense against phishing?",
    options: [
      "It completely prevents attackers from sending you fake emails.",
      "It makes credentials useless because an attacker cannot bypass the secondary verification factor alone.",
      "It decrypts all incoming spam automatically.",
      "It blocks typosquatted domains on the router."
    ],
    answer: 1
  },
  {
    q: "An SMS message from an unknown number states: 'Package delayed. Pay $1.50 clearance fee at bit.ly/3xPq9'. This is an example of:",
    options: [
      "Smishing (SMS Phishing)",
      "Zero-day hardware vulnerability",
      "Vishing (Voice Phishing)",
      "SQL injection attack"
    ],
    answer: 0
  }
];

let currentQuizIndex = 0;
let userScore = 0;
let selectedOption = null;

const quizQuestion = document.getElementById("quiz-question");
const quizOptions = document.getElementById("quiz-options");
const quizIdx = document.getElementById("quiz-idx");
const quizNextBtn = document.getElementById("quiz-next-btn");
const quizQuestionContainer = document.getElementById("quiz-question-container");
const quizResultContainer = document.getElementById("quiz-result-container");
const resultScore = document.getElementById("result-score");
const resultTitle = document.getElementById("result-title");
const resultDesc = document.getElementById("result-desc");
const btnRestartQuiz = document.getElementById("btn-restart-quiz");
const btnGetCertificate = document.getElementById("btn-get-certificate");
const certificateContainer = document.getElementById("certificate-container");
const certDate = document.getElementById("cert-date");

function renderQuizQuestion(index) {
  selectedOption = null;
  quizNextBtn.disabled = true;
  quizIdx.textContent = index + 1;

  const q = quizData[index];
  quizQuestion.textContent = q.q;
  quizOptions.innerHTML = "";

  q.options.forEach((opt, optIndex) => {
    const btn = document.createElement("button");
    btn.className = "quiz-option-btn";
    btn.textContent = opt;
    btn.addEventListener("click", () => {
      document.querySelectorAll(".quiz-option-btn").forEach((b) => b.classList.remove("selected"));
      btn.classList.add("selected");
      selectedOption = optIndex;
      quizNextBtn.disabled = false;
    });
    quizOptions.appendChild(btn);
  });
}

quizNextBtn.addEventListener("click", () => {
  if (selectedOption === null) return;

  if (selectedOption === quizData[currentQuizIndex].answer) {
    userScore++;
  }

  currentQuizIndex++;

  if (currentQuizIndex < quizData.length) {
    renderQuizQuestion(currentQuizIndex);
  } else {
    showQuizResults();
  }
});

function showQuizResults() {
  quizQuestionContainer.classList.add("hidden");
  quizResultContainer.classList.remove("hidden");

  resultScore.textContent = userScore + " / " + quizData.length;

  if (userScore >= 4) {
    resultTitle.textContent = "Assessment Passed";
    resultDesc.textContent = "Excellent work. You demonstrated strong vigilance against social engineering tactics.";
    btnGetCertificate.classList.remove("hidden");
  } else {
    resultTitle.textContent = "Assessment Needs Improvement";
    resultDesc.textContent = "Score under 80%. Review the indicators and guidelines above and retake the test.";
    btnGetCertificate.classList.add("hidden");
  }
}

btnRestartQuiz.addEventListener("click", () => {
  currentQuizIndex = 0;
  userScore = 0;
  selectedOption = null;
  quizResultContainer.classList.add("hidden");
  certificateContainer.classList.add("hidden");
  quizQuestionContainer.classList.remove("hidden");
  renderQuizQuestion(0);
});

btnGetCertificate.addEventListener("click", () => {
  const entered = prompt("Enter your name for the training certificate:", "Security Champion");
  const userName = entered && entered.trim().length > 0 ? entered.trim() : "Security Champion";

  document.getElementById("cert-name").textContent = userName;
  certDate.textContent = new Date().toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric"
  });

  certificateContainer.classList.remove("hidden");
  certificateContainer.scrollIntoView({ behavior: "smooth" });
});

loadScenario(0);
analyzeUrl(urlInput.value);
renderQuizQuestion(0);