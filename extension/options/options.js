import { DEFAULT_SETTINGS } from '../config/rules.js';

let currentSettings = { ...DEFAULT_SETTINGS };

document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  setupListeners();
});

async function loadSettings() {
  const data = await chrome.storage.local.get('settings');
  currentSettings = { ...DEFAULT_SETTINGS, ...(data.settings || {}) };

  // Set checkboxes
  document.getElementById('protectionEnabled').checked = currentSettings.protectionEnabled ?? true;
  document.getElementById('enableUrlAnalysis').checked = currentSettings.enableUrlAnalysis ?? true;
  document.getElementById('enableTyposquatting').checked = currentSettings.enableTyposquatting ?? true;
  document.getElementById('enableDomAnalysis').checked = currentSettings.enableDomAnalysis ?? true;
  document.getElementById('enableSocialEngineering').checked = currentSettings.enableSocialEngineering ?? true;
  document.getElementById('enableDownloadContext').checked = currentSettings.enableDownloadContext ?? true;
  document.getElementById('enableRedirectAnalysis').checked = currentSettings.enableRedirectAnalysis ?? true;
  document.getElementById('enableReputationLayer').checked = currentSettings.enableReputationLayer ?? true;
  document.getElementById('developerMode').checked = currentSettings.developerMode ?? false;

  // Sensitivity radio
  const radios = document.getElementsByName('detectionSensitivity');
  for (const r of radios) {
    if (r.value === (currentSettings.detectionSensitivity || 'BALANCED')) {
      r.checked = true;
    }
  }

  // Sliders
  const warningSlider = document.getElementById('warningThreshold');
  const blockSlider = document.getElementById('blockThreshold');
  
  warningSlider.value = currentSettings.warningThreshold ?? 70;
  document.getElementById('warningVal').textContent = warningSlider.value;

  blockSlider.value = currentSettings.blockThreshold ?? 90;
  document.getElementById('blockVal').textContent = blockSlider.value;

  // Render tag clouds
  renderTags('allowlistContainer', currentSettings.allowlist || [], (val) => {
    currentSettings.allowlist = (currentSettings.allowlist || []).filter(d => d !== val);
    saveSettings();
    loadSettings();
  });

  renderTags('blocklistContainer', currentSettings.blocklist || [], (val) => {
    currentSettings.blocklist = (currentSettings.blocklist || []).filter(d => d !== val);
    saveSettings();
    loadSettings();
  });
}

function setupListeners() {
  // Checkbox bindings
  const checkboxMap = [
    { id: 'protectionEnabled', key: 'protectionEnabled' },
    { id: 'enableUrlAnalysis', key: 'enableUrlAnalysis' },
    { id: 'enableTyposquatting', key: 'enableTyposquatting' },
    { id: 'enableDomAnalysis', key: 'enableDomAnalysis' },
    { id: 'enableSocialEngineering', key: 'enableSocialEngineering' },
    { id: 'enableDownloadContext', key: 'enableDownloadContext' },
    { id: 'enableRedirectAnalysis', key: 'enableRedirectAnalysis' },
    { id: 'enableReputationLayer', key: 'enableReputationLayer' },
    { id: 'developerMode', key: 'developerMode' }
  ];

  checkboxMap.forEach(({ id, key }) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('change', (e) => {
        currentSettings[key] = e.target.checked;
        saveSettings();
      });
    }
  });

  // Radio bindings
  const radios = document.getElementsByName('detectionSensitivity');
  for (const r of radios) {
    r.addEventListener('change', (e) => {
      if (e.target.checked) {
        currentSettings.detectionSensitivity = e.target.value;
        saveSettings();
      }
    });
  }

  // Slider bindings
  const warningSlider = document.getElementById('warningThreshold');
  warningSlider.addEventListener('input', (e) => {
    document.getElementById('warningVal').textContent = e.target.value;
    currentSettings.warningThreshold = parseInt(e.target.value, 10);
    saveSettings();
  });

  const blockSlider = document.getElementById('blockThreshold');
  blockSlider.addEventListener('input', (e) => {
    document.getElementById('blockVal').textContent = e.target.value;
    currentSettings.blockThreshold = parseInt(e.target.value, 10);
    saveSettings();
  });

  // Allowlist add
  document.getElementById('addAllowlistBtn').addEventListener('click', () => {
    const input = document.getElementById('allowlistInput');
    const val = input.value.trim().toLowerCase();
    if (val) {
      currentSettings.allowlist = currentSettings.allowlist || [];
      if (!currentSettings.allowlist.includes(val)) {
        currentSettings.allowlist.push(val);
        input.value = '';
        saveSettings();
        loadSettings();
      }
    }
  });

  // Blocklist add
  document.getElementById('addBlocklistBtn').addEventListener('click', () => {
    const input = document.getElementById('blocklistInput');
    const val = input.value.trim().toLowerCase();
    if (val) {
      currentSettings.blocklist = currentSettings.blocklist || [];
      if (!currentSettings.blocklist.includes(val)) {
        currentSettings.blocklist.push(val);
        input.value = '';
        saveSettings();
        loadSettings();
      }
    }
  });

  // Reset
  document.getElementById('resetDefaultsBtn').addEventListener('click', async () => {
    currentSettings = { ...DEFAULT_SETTINGS };
    await chrome.storage.local.set({ settings: currentSettings });
    loadSettings();
    showSaveIndicator();
  });

  // Clear History
  document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
    await chrome.storage.local.set({ history: [] });
    showSaveIndicator();
  });
}

function renderTags(containerId, list, onRemove) {
  const container = document.getElementById(containerId);
  container.textContent = '';

  if (!list || list.length === 0) {
    const emptyMsg = document.createElement('span');
    emptyMsg.style.color = '#64748B';
    emptyMsg.style.fontSize = '11px';
    emptyMsg.textContent = 'No entries configured.';
    container.appendChild(emptyMsg);
    return;
  }

  list.forEach(item => {
    const tag = document.createElement('div');
    tag.className = 'tag-item';

    const span = document.createElement('span');
    span.textContent = item;

    const removeBtn = document.createElement('span');
    removeBtn.className = 'tag-remove';
    removeBtn.textContent = '×';
    removeBtn.onclick = () => onRemove(item);

    tag.appendChild(span);
    tag.appendChild(removeBtn);
    container.appendChild(tag);
  });
}

async function saveSettings() {
  await chrome.storage.local.set({ settings: currentSettings });
  showSaveIndicator();
}

function showSaveIndicator() {
  const status = document.getElementById('saveStatus');
  status.classList.add('show');
  setTimeout(() => {
    status.classList.remove('show');
  }, 1800);
}
