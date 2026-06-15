class HeaderDoctorApp {
    constructor() {
        this.urlInput = document.getElementById('url-input');
        this.scanBtn = document.getElementById('scan-button');
        this.resultsSection = document.getElementById('results-section');
        this.loadingDiv = document.getElementById('loading');
        this.errorDiv = document.getElementById('error');
        this.historyList = document.getElementById('recent-scans-list');

        // Permission modal elements
        this.permissionModal = document.getElementById('permission-modal');
        this.permissionAllowBtn = document.getElementById('permission-allow');
        this.permissionDenyBtn = document.getElementById('permission-deny');
        this.modalClose = document.querySelector('.modal-close');

        this.currentUrl = '';
        this.pendingScanOptions = {};
        this.currentRecommendations = [];
        this.lastScanData = null;
        this.injectedHeaders = [];

        this.bindEvents();

        // Load scan history on page load
        this.loadScanHistory();
        this.loadTopScores();

        // Add click handlers for popular scans
        this.bindPopularScans();

        // New features
        this.initDarkMode();
        this.renderInjectedHeaders();
    }

    showPermissionModal() {
        if (this.permissionModal) {
            // Update the target domain in the modal
            const targetDomainElement = document.getElementById('target-domain');
            if (targetDomainElement && this.urlInput.value.trim()) {
                try {
                    const url = new URL(this.urlInput.value.trim().startsWith('http') ?
                        this.urlInput.value.trim() :
                        'https://' + this.urlInput.value.trim());
                    targetDomainElement.textContent = url.hostname;
                } catch (e) {
                    targetDomainElement.textContent = this.urlInput.value.trim();
                }
            }

            this.permissionModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    hidePermissionModal() {
        if (this.permissionModal) {
            this.permissionModal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }

    grantPermission() {
        this.hidePermissionModal();
        // Proceed with internal URL scanning
        this.pendingScanOptions.scan_internal_urls = true;
        this.performScan(this.currentUrl, this.pendingScanOptions);
    }

    denyPermission() {
        this.hidePermissionModal();
        // Proceed with regular scanning only
        this.pendingScanOptions.scan_internal_urls = false;
        this.performScan(this.currentUrl, this.pendingScanOptions);
    }

    bindEvents() {
        // Listen to the form submit event to prevent page reload
        const form = document.getElementById('scanner-form');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleScan();
            });
        }

        this.scanBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.handleScan();
        });

        // Permission modal events
        if (this.modalClose) {
            this.modalClose.addEventListener('click', () => this.hidePermissionModal());
        }

        if (this.permissionModal) {
            this.permissionModal.addEventListener('click', (e) => {
                if (e.target === this.permissionModal) {
                    this.hidePermissionModal();
                }
            });
        }

        if (this.permissionAllowBtn) {
            this.permissionAllowBtn.addEventListener('click', () => this.grantPermission());
        }

        if (this.permissionDenyBtn) {
            this.permissionDenyBtn.addEventListener('click', () => this.denyPermission());
        }

        // Export buttons
        const exportJsonBtn = document.getElementById('export-json-btn');
        if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => this.exportJSON());
        const exportTextBtn = document.getElementById('export-text-btn');
        if (exportTextBtn) exportTextBtn.addEventListener('click', () => this.exportText());
        const exportPdfBtn = document.getElementById('export-pdf-btn');
        if (exportPdfBtn) exportPdfBtn.addEventListener('click', () => this.exportPDF());

        // Custom Header Injector
        const addInjectBtn = document.getElementById('add-inject-header-btn');
        if (addInjectBtn) addInjectBtn.addEventListener('click', () => this.addInjectedHeader());

        // Delegated events for recommendations copy & expand
        const recsContainer = document.getElementById('recommendations');
        if (recsContainer) {
            recsContainer.addEventListener('click', (e) => {
                const btn = e.target.closest('.copy-rec-btn');
                if (btn) {
                    const text = btn.dataset.text;
                    if (text) {
                        navigator.clipboard.writeText(text).then(() => this.showToast('Copied to clipboard!'));
                    }
                    return;
                }
                const header = e.target.closest('.rec-header-row');
                if (header) {
                    const item = header.closest('.recommendation-item');
                    if (item) item.classList.toggle('expanded');
                }
            });
        }
    }

    initDarkMode() {
        const toggleBtn = document.getElementById('dark-mode-toggle');
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
        }
        if (toggleBtn) {
            toggleBtn.addEventListener('click', (e) => {
                e.preventDefault();
                document.body.classList.toggle('dark-mode');
                localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
            });
        }
    }

    addInjectedHeader() {
        const nameInput = document.getElementById('inject-header-name');
        const valueInput = document.getElementById('inject-header-value');
        if (!nameInput || !valueInput) return;

        const name = nameInput.value.trim();
        const value = valueInput.value.trim();

        if (!name || !value) {
            this.showToast('Please provide both header name and value.');
            return;
        }

        this.injectedHeaders.push({ name, value });
        nameInput.value = '';
        valueInput.value = '';
        this.renderInjectedHeaders();
        this.showToast('Custom header added (effective on next scan).');
    }

    removeInjectedHeader(index) {
        this.injectedHeaders.splice(index, 1);
        this.renderInjectedHeaders();
    }

    renderInjectedHeaders() {
        const list = document.getElementById('injected-headers-list');
        if (!list) return;

        list.innerHTML = '';
        if (this.injectedHeaders.length === 0) {
            list.innerHTML = '<p class="text-muted" style="margin:0; font-style:italic; font-size: 0.9em;">No custom headers added yet.</p>';
            return;
        }

        this.injectedHeaders.forEach((h, idx) => {
            const div = document.createElement('div');
            div.className = 'injected-header-item';
            div.innerHTML = `
                <div><strong>${this.escapeHtml(h.name)}</strong>: ${this.escapeHtml(h.value)}</div>
                <button type="button" class="inject-remove-btn" title="Remove custom header">&times;</button>
            `;
            const removeBtn = div.querySelector('.inject-remove-btn');
            if (removeBtn) {
                removeBtn.addEventListener('click', () => this.removeInjectedHeader(idx));
            }
            list.appendChild(div);
        });
    }

    bindPopularScans() {
        const popularScans = document.querySelectorAll('#popular-scans-list .history-item');
        popularScans.forEach(item => {
            item.addEventListener('click', () => {
                this.urlInput.value = item.dataset.url;
                // Auto-trigger the scan for popular sites
                this.handleScan();
            });
        });
    }

    async handleScan() {
        const url = this.urlInput.value.trim();
        if (!url) {
            this.showError('Please enter a valid URL');
            return;
        }

        this.currentUrl = url;

        // Get checkbox states
        const analyzeContentCheckbox = document.getElementById('analyze-content');
        const bypassCacheCheckbox = document.getElementById('bypass-cache');
        const scanInternalUrlsCheckbox = document.getElementById('scan-internal-urls');

        const scanOptions = {
            analyze_content: analyzeContentCheckbox ? analyzeContentCheckbox.checked : false,
            bypass_cache: bypassCacheCheckbox ? bypassCacheCheckbox.checked : false,
            scan_internal_urls: scanInternalUrlsCheckbox ? scanInternalUrlsCheckbox.checked : false
        };

        // If internal URL scanning is requested, show permission modal
        if (scanOptions.scan_internal_urls) {
            this.pendingScanOptions = scanOptions;
            this.showPermissionModal();
            return;
        }

        // Regular scan
        this.performScan(url, scanOptions);
    }

    async performScan(url, options = {}) {
        this.showLoading();
        this.hideError();
        this.hideResults();

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    analyze_content: options.analyze_content || false,
                    bypass_cache: options.bypass_cache || false,
                    scan_internal_urls: options.scan_internal_urls || false,
                    injected_headers: this.injectedHeaders
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to analyze headers');
            }

            this.displayResults(data);
            this.loadScanHistory(); // Refresh history
            this.loadTopScores(); // Refresh top scores

        } catch (error) {
            console.error('Scan error:', error);
            this.showError(error.message);
        } finally {
            this.hideLoading();
        }
    }

    displayResults(data) {
        this.showResults();
        this.lastScanData = data;

        // Show export bar inside the internal results section, or keep it global
        const exportBar = document.getElementById('export-bar');
        if (exportBar) {
            exportBar.style.display = 'flex';
            exportBar.style.justifyContent = 'center';
            exportBar.style.marginTop = '20px';
        }

        if (data.scan_type === 'internal_urls') {
            this.displayInternalResults(data);
        } else {
            this.displayRegularResults(data);
        }
    }

    displayRegularResults(data) {
        // Hide any internal results container
        this.hideInternalResults();

        // Show Cloudflare block warning if detected
        this.displayCloudflareStatus(data);

        const analysis = data.analysis;

        // Update main results
        document.getElementById('analyzed-url').textContent = data.url;
        document.getElementById('status-code').textContent = data.status_code;
        document.getElementById('headers-found').textContent = Object.keys(analysis.present_headers).length;
        document.getElementById('score-value').textContent = `${analysis.percentage}%`;

        const gradeEl = document.getElementById('grade-value');
        if (gradeEl) {
            const grade = this.getGrade(analysis.percentage);
            gradeEl.textContent = grade;
            // Clear old grade classes
            gradeEl.className = 'score-grade';
            gradeEl.classList.add(`grade-${grade.replace('+', 'plus').toLowerCase()}`);
        }

        // Update score styling and percentage fill
        const scoreElement = document.getElementById('score-value');
        scoreElement.className = `score-value ${this.getScoreClass(analysis.percentage)}`;

        // Set the percentage for the visual circle fill
        const scoreCircle = document.querySelector('.score-circle');
        if (scoreCircle) {
            scoreCircle.style.setProperty('--score-percent', `${analysis.percentage}%`);
        }

        // Display category scores
        this.displayCategoryScores(analysis.category_scores);

        // Display present headers
        this.displayPresentHeaders(analysis.present_headers);

        // Display missing headers and recommendations
        this.displayRecommendations(analysis.recommendations);

        // Display server config
        this.displayServerConfig(analysis.recommendations);

        // Display content analysis if available
        if (data.content_analysis) {
            this.displayContentAnalysis(data.content_analysis);
        }
    }

    displayCloudflareStatus(data) {
        // Remove any existing cloudflare banner
        const existing = document.getElementById('cloudflare-banner');
        if (existing) existing.remove();

        if (!data.cloudflare_blocked) return;

        const info = data.cloudflare_info;
        const banner = document.createElement('div');
        banner.id = 'cloudflare-banner';
        banner.className = 'cloudflare-banner';
        banner.innerHTML = `
            <div class="cf-banner-icon">🛡️</div>
            <div class="cf-banner-content">
                <h4>Cloudflare Protection Detected</h4>
                <p>${this.escapeHtml(info.message)}</p>
                <div class="cf-banner-meta">
                    ${info.cf_ray ? `<span class="cf-ray">CF-Ray: ${this.escapeHtml(info.cf_ray)}</span>` : ''}
                    <span class="cf-indicators">${info.indicators.map(i => `<span class="cf-tag">${i.replace(/_/g, ' ')}</span>`).join('')}</span>
                </div>
            </div>
        `;

        // Insert at top of results section
        const resultsSection = document.getElementById('results-section');
        if (resultsSection) {
            const firstChild = resultsSection.querySelector('.results-header') || resultsSection.firstChild;
            if (firstChild && firstChild.nextSibling) {
                resultsSection.insertBefore(banner, firstChild.nextSibling);
            } else {
                resultsSection.prepend(banner);
            }
        }
    }

    displayInternalResults(data) {
        // Hide regular results
        this.hideRegularResults();

        // Show or create internal results container
        let internalContainer = document.getElementById('internal-results-container');
        if (!internalContainer) {
            internalContainer = document.createElement('div');
            internalContainer.id = 'internal-results-container';
            internalContainer.className = 'internal-results-container';
            this.resultsSection.appendChild(internalContainer);
        }

        internalContainer.style.display = 'block';

        const multiScanResults = data.multi_scan_results;

        internalContainer.innerHTML = `
            <div class="internal-results-header">
                <h2>🔍 Internal URL Scan Results</h2>
                <div class="scan-summary">
                    <div class="summary-stat">
                        <span class="stat-value">${multiScanResults.total_pages}</span>
                        <span class="stat-label">Pages Scanned</span>
                    </div>
                    <div class="summary-stat">
                        <span class="stat-value">${multiScanResults.successful_scans}</span>
                        <span class="stat-label">Successful</span>
                    </div>
                    <div class="summary-stat">
                        <span class="stat-value ${this.getScoreClass(multiScanResults.average_score)}">${multiScanResults.average_score}%</span>
                        <span class="stat-label">Average Score</span>
                    </div>
                </div>
            </div>

            <div class="discovered-urls">
                <h3>📋 Discovered URLs</h3>
                <div class="urls-list">
                    ${data.discovered_urls.map(url => `
                        <div class="url-item">
                            <span class="url-link">${url}</span>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="page-results">
                <h3>📊 Individual Page Results</h3>
                <div class="pages-grid">
                    ${multiScanResults.page_results.map(result => {
            if (!result.success) {
                return `
                                <div class="page-result error">
                                    <div class="page-url">${result.url}</div>
                                    <div class="page-error">❌ ${result.error}</div>
                                </div>
                            `;
            }

            const analysis = result.analysis;
            return `
                            <div class="page-result">
                                <div class="page-header">
                                    <div class="page-url">${result.url}</div>
                                    <div class="page-score ${this.getScoreClass(analysis.percentage)}">${analysis.percentage}%</div>
                                </div>
                                <div class="page-stats">
                                    <span>Headers: ${Object.keys(analysis.present_headers).length}</span>
                                    <span>Missing: ${analysis.recommendations.length}</span>
                                    <span>Status: ${result.status_code}</span>
                                </div>

                                <div class="page-internal-details">
                                    <div class="internal-section present">
                                        <h4>✅ Present Headers</h4>
                                        <div class="present-headers-list">
                                            ${Object.entries(analysis.present_headers).map(([header, data]) => `
                                                <div class="header-item present compact">
                                                    <span class="header-name">${header}</span>
                                                    <span class="header-value" title="${this.escapeHtml(data.value)}">${this.escapeHtml(data.value)}</span>
                                                </div>
                                            `).join('') || '<p class="text-muted">No security headers found.</p>'}
                                        </div>
                                    </div>

                                    <div class="internal-section issues">
                                        <h4>🚨 Recommended Headers</h4>
                                        <div class="page-issues">
                                            ${analysis.recommendations.map(rec => `
                                                <div class="recommendation-item expanded">
                                                    <div class="rec-header-row" title="Click to expand/collapse">
                                                        <h5>${rec.header}</h5>
                                                        <div class="severity-badge ${rec.severity}">${rec.severity.toUpperCase()}</div>
                                                    </div>
                                                    <div class="rec-details">
                                                        <p>${rec.description}</p>
                                                        <div class="recommendation-value">
                                                            <div>
                                                                <strong>Recommended:</strong>
                                                                <code>${this.escapeHtml(rec.recommendation)}</code>
                                                            </div>
                                                            <button class="copy-rec-btn" data-text="${this.escapeHtml(rec.header + ': ' + rec.recommendation)}" title="Copy recommendation">📋</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            `).join('') || '<p class="text-muted">No missing headers. Great job!</p>'}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `;
        }).join('')}
                </div>
            </div>

            <div class="common-issues">
                <h3>🚨 Common Issues Across Pages</h3>
                <div class="issues-grid">
                    ${Object.entries(multiScanResults.common_issues).map(([header, count]) => `
                        <div class="common-issue">
                            <div class="issue-header">${header}</div>
                            <div class="issue-count">${count}/${multiScanResults.successful_scans} pages</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="header-consistency">
                <h3>🔄 Header Consistency Analysis</h3>
                <div class="consistency-grid">
                    ${Object.entries(multiScanResults.header_consistency).map(([header, data]) => {
            if (data.consistent) {
                return `
                                <div class="consistency-item consistent">
                                    <div class="consistency-header">${header}</div>
                                    <div class="consistency-status">✅ Consistent (${data.count} pages)</div>
                                    <div class="consistency-value">${data.value || 'N/A'}</div>
                                </div>
                            `;
            } else {
                return `
                                <div class="consistency-item inconsistent">
                                    <div class="consistency-header">${header}</div>
                                    <div class="consistency-status">⚠️ Inconsistent (${data.count} pages)</div>
                                    <div class="consistency-values">
                                        ${data.values.slice(0, 2).map(val => `<div class="value-variant">${val}</div>`).join('')}
                                        ${data.values.length > 2 ? `<div class="value-variant">+${data.values.length - 2} more...</div>` : ''}
                                    </div>
                                </div>
                            `;
            }
        }).join('')}
                </div>
            </div>
        `;

        // Attach expand/collapse and copy handlers for internal results
        internalContainer.addEventListener('click', (e) => {
            const btn = e.target.closest('.copy-rec-btn');
            if (btn) {
                const text = btn.dataset.text;
                if (text) {
                    navigator.clipboard.writeText(text).then(() => this.showToast('Copied to clipboard!'));
                }
                return;
            }
            const header = e.target.closest('.rec-header-row');
            if (header) {
                const item = header.closest('.recommendation-item');
                if (item) item.classList.toggle('expanded');
            }
        });
    }

    displayCategoryScores(categoryScores) {
        const container = document.getElementById('category-scores');
        if (!container || !categoryScores) return;

        container.innerHTML = Object.entries(categoryScores).map(([key, category]) => `
            <div class="category-card">
                <div class="category-header">
                    <h3>${category.name}</h3>
                    <div class="category-score ${this.getScoreClass(category.percentage)}">${category.percentage}%</div>
                </div>
                <p class="category-description">${category.description}</p>
                <div class="category-stats">
                    <span>${category.present_count}/${category.total_count} headers present</span>
                </div>
            </div>
        `).join('');
    }

    displayPresentHeaders(presentHeaders) {
        const container = document.getElementById('present-headers');
        if (!container) return;

        container.innerHTML = Object.entries(presentHeaders).map(([header, data]) => `
            <div class="header-item present">
                <div class="header-name">${header}</div>
                <div class="header-value">${this.escapeHtml(data.value)}</div>
                <div class="header-status good">✓ Present</div>
            </div>
        `).join('');
    }

    displayRecommendations(recommendations) {
        // Display in missing headers section
        const missingContainer = document.getElementById('missing-headers');
        if (missingContainer) {
            missingContainer.innerHTML = recommendations.map(rec => `
                <div class="header-item missing">
                    <div class="header-name">${rec.header}</div>
                    <div class="header-description">${rec.description}</div>
                    <div class="header-value">Recommended: ${this.escapeHtml(rec.recommendation)}</div>
                    <div class="header-status ${rec.severity}">${rec.severity.toUpperCase()}</div>
                </div>
            `).join('');
        }

        // Also display in general recommendations section
        const recContainer = document.getElementById('recommendations');
        if (recContainer) {
            recContainer.innerHTML = recommendations.map(rec => `
                <div class="recommendation-item">
                    <div class="rec-header-row" title="Click to expand/collapse">
                        <h4>${rec.header}</h4>
                        <div class="severity-badge ${rec.severity}">${rec.severity.toUpperCase()}</div>
                    </div>
                    <div class="rec-details">
                        <p>${rec.description}</p>
                        <div class="recommendation-value">
                            <div>
                                <strong>Recommended value:</strong>
                                <code>${this.escapeHtml(rec.recommendation)}</code>
                            </div>
                            <button class="copy-rec-btn" data-text="${this.escapeHtml(rec.header + ': ' + rec.recommendation)}" title="Copy recommendation">📋</button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    }

    displayServerConfig(recommendations) {
        // Store recommendations for server type switching
        this.currentRecommendations = recommendations;

        const configContainer = document.getElementById('config-output');
        const serverTypeSelect = document.getElementById('server-type');

        if (!configContainer || !serverTypeSelect) return;

        const serverType = serverTypeSelect.value || 'nginx';

        let configText = '';

        if (recommendations.length === 0) {
            configText = '# All recommended headers are already present!';
        } else {
            switch (serverType) {
                case 'nginx':
                    configText = '# Add these to your server {} or location {} block\n\n' +
                        recommendations.map(rec =>
                            `# ${rec.description}\nadd_header ${rec.header} "${rec.recommendation}";\n`
                        ).join('\n');
                    break;
                case 'apache':
                    configText = '# Add to your .htaccess or <VirtualHost> block\n# Requires: mod_headers\n\n' +
                        recommendations.map(rec =>
                            `# ${rec.description}\nHeader always set ${rec.header} "${rec.recommendation}"\n`
                        ).join('\n');
                    break;
                case 'iis':
                    configText = `<!-- Add to your web.config -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n` +
                        recommendations.map(rec =>
                            `      <!-- ${rec.description} -->\n      <add name="${rec.header}" value="${rec.recommendation}" />`
                        ).join('\n') +
                        `\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`;
                    break;
            }
        }

        configContainer.innerHTML = `<pre><code>${this.escapeHtml(configText)}</code></pre>`;

        // Show the copy button and set up copy functionality
        const copyBtn = document.getElementById('copy-config-btn');
        if (copyBtn) {
            copyBtn.style.display = configText ? 'flex' : 'none';

            // Remove existing event listeners
            const newCopyBtn = copyBtn.cloneNode(true);
            copyBtn.parentNode.replaceChild(newCopyBtn, copyBtn);

            // Add new event listener
            newCopyBtn.addEventListener('click', () => this.copyConfigToClipboard(configText));
        }

        // Add event listener for server type changes if not already added
        if (!serverTypeSelect.hasAttribute('data-listener-added')) {
            serverTypeSelect.addEventListener('change', () => {
                this.displayServerConfig(this.currentRecommendations);
            });
            serverTypeSelect.setAttribute('data-listener-added', 'true');
        }
    }

    displayContentAnalysis(contentAnalysis) {
        const section = document.getElementById('content-analysis-section');
        const container = document.getElementById('content-analysis-results');
        if (!section || !container || !contentAnalysis.domains_found) return;

        const domains = contentAnalysis.domains_found;
        const features = contentAnalysis.page_features;

        const domainHtml = Object.entries(domains)
            .filter(([, domainList]) => domainList.length > 0)
            .map(([directive, domainList]) => `
                <div class="domain-group">
                    <h4>${directive}</h4>
                    <ul class="domain-list">
                        ${domainList.map(domain => `<li>${this.escapeHtml(domain)}</li>`).join('')}
                    </ul>
                </div>
            `).join('');

        const activeFeatures = Object.entries(features)
            .filter(([, value]) => typeof value === 'boolean' && value)
            .map(([key]) => `<div class="feature-item"><span class="feature-status detected"></span><span class="feature-name">${key.replace(/_/g, ' ')}</span></div>`)
            .join('');

        container.innerHTML = `
            ${domainHtml ? `<div class="domains-found"><h4>External Domains Detected</h4>${domainHtml}</div>` : ''}
            ${activeFeatures ? `<div class="page-features"><h4>Page Features Detected</h4><div class="features-grid">${activeFeatures}</div></div>` : ''}
        `;

        section.style.display = (domainHtml || activeFeatures) ? 'block' : 'none';
    }

    getDisplayHost(url) {
        try {
            const u = new URL(url.startsWith('http') ? url : 'https://' + url);
            return u.hostname;
        } catch (e) {
            return url;
        }
    }

    async loadScanHistory() {
        if (!this.historyList) return;
        try {
            const response = await fetch('/history');
            if (!response.ok) return;
            const data = await response.json();

            if (data.history && data.history.length > 0) {
                this.historyList.innerHTML = data.history.slice(0, 5).map(item => `
                    <div class="history-item" data-url="${this.escapeHtml(item.url)}">
                        <div class="history-url" title="${this.escapeHtml(item.url)}">${this.escapeHtml(this.getDisplayHost(item.url))}</div>
                        <div class="history-details">
                            <span class="history-score ${this.getScoreClass(item.score)}">${item.score}%</span>
                            <span class="history-time">${item.relative_time}</span>
                        </div>
                    </div>
                `).join('');

                // Add click handlers to history items
                this.historyList.querySelectorAll('.history-item').forEach(item => {
                    item.addEventListener('click', () => {
                        this.urlInput.value = item.dataset.url;
                    });
                });
            } else {
                this.historyList.innerHTML = '<p class="no-history">No recent scans</p>';
            }
        } catch (error) {
            console.error('Failed to load scan history:', error);
            this.historyList.innerHTML = '<p class="no-history">No recent scans</p>';
        }
    }

    async loadTopScores() {
        const topList = document.getElementById('top-scores-list');
        if (!topList) return;
        try {
            const response = await fetch('/top-scores');
            if (!response.ok) return;
            const data = await response.json();

            if (data.top_sites && data.top_sites.length > 0) {
                topList.innerHTML = data.top_sites.map(item => `
                    <div class="history-item top-score-item" data-url="${this.escapeHtml(item.url)}">
                        <div class="history-url" title="${this.escapeHtml(item.url)}">${this.escapeHtml(this.getDisplayHost(item.url))}</div>
                        <div class="history-details">
                            <span class="history-score ${this.getScoreClass(item.score)}">${item.score}%</span>
                        </div>
                    </div>
                `).join('');

                topList.querySelectorAll('.history-item').forEach(item => {
                    item.addEventListener('click', () => {
                        this.urlInput.value = item.dataset.url;
                    });
                });
            }
        } catch (e) {
            // silently fail
        }
    }

    showLoading() {
        this.loadingDiv.style.display = 'block';
        this.scanBtn.disabled = true;
        const btnText = this.scanBtn.querySelector('.button-text');
        const spinner = this.scanBtn.querySelector('.spinner');
        if (btnText) btnText.textContent = 'Scanning...';
        if (spinner) spinner.style.display = 'inline-block';
    }

    hideLoading() {
        this.loadingDiv.style.display = 'none';
        this.scanBtn.disabled = false;
        const btnText = this.scanBtn.querySelector('.button-text');
        const spinner = this.scanBtn.querySelector('.spinner');
        if (btnText) btnText.textContent = 'Scan Headers';
        if (spinner) spinner.style.display = 'none';
    }

    showResults() {
        this.resultsSection.style.display = 'block';
    }

    hideResults() {
        this.resultsSection.style.display = 'none';
    }

    showError(message) {
        const errorMessage = this.errorDiv.querySelector('.error-message');
        if (errorMessage) {
            errorMessage.textContent = message;
        } else {
            this.errorDiv.textContent = message;
        }
        this.errorDiv.style.display = 'block';
    }

    hideError() {
        this.errorDiv.style.display = 'none';
    }

    hideInternalResults() {
        const internalResultsContainer = document.getElementById('internal-results-container');
        if (internalResultsContainer) {
            internalResultsContainer.style.display = 'none';
        }
    }

    hideRegularResults() {
        // Hide the regular results cards/sections
        const regularSections = [
            '.results-header',
            '.category-scores',
            '.results-grid',
            '.content-analysis-section',
            '.page-features-section',
            '.recommendations-section',
            '.config-section'
        ];

        regularSections.forEach(selector => {
            const element = this.resultsSection.querySelector(selector);
            if (element) {
                element.style.display = 'none';
            }
        });
    }

    getScoreClass(score) {
        if (score >= 80) return 'good';
        if (score >= 60) return 'warning';
        return 'poor';
    }

    async copyConfigToClipboard(configText) {
        try {
            await navigator.clipboard.writeText(configText);

            // Update button text temporarily
            const copyBtn = document.getElementById('copy-config-btn');
            const originalText = copyBtn.innerHTML;
            copyBtn.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            copyBtn.disabled = true;

            setTimeout(() => {
                copyBtn.innerHTML = originalText;
                copyBtn.disabled = false;
            }, 2000);

        } catch (err) {
            console.error('Failed to copy configuration:', err);

            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = configText;
            document.body.appendChild(textArea);
            textArea.select();

            try {
                document.execCommand('copy');
                const copyBtn = document.getElementById('copy-config-btn');
                const originalText = copyBtn.innerHTML;
                copyBtn.innerHTML = '<span class="copy-icon">✅</span> Copied!';
                copyBtn.disabled = true;

                setTimeout(() => {
                    copyBtn.innerHTML = originalText;
                    copyBtn.disabled = false;
                }, 2000);
            } catch (fallbackErr) {
                alert('Copy failed. Please select the text manually.');
            }

            document.body.removeChild(textArea);
        }
    }

    getGrade(score) {
        if (score >= 95) return 'A+';
        if (score >= 85) return 'A';
        if (score >= 70) return 'B';
        if (score >= 50) return 'C';
        if (score >= 30) return 'D';
        return 'F';
    }

    exportJSON() {
        if (!this.lastScanData) return;
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.lastScanData, null, 2));
        const a = document.createElement('a');
        a.href = dataStr;
        a.download = "headerdoctor_report.json";
        a.click();
    }

    exportText() {
        if (!this.lastScanData) return;
        const analysis = this.lastScanData.analysis || this.lastScanData;
        let text = `HeaderDoctor Report for ${this.lastScanData.url}\n`;
        text += `Score: ${analysis.percentage}%\n\n`;
        text += `Present Headers:\n`;
        Object.entries(analysis.present_headers || {}).forEach(([h, d]) => text += `- ${h}: ${d.value}\n`);
        text += `\nMissing/Vulnerable Headers:\n`;
        (analysis.recommendations || []).forEach(r => text += `- ${r.header} (${r.severity}): ${r.description}\n`);
        const dataStr = "data:text/plain;charset=utf-8," + encodeURIComponent(text);
        const a = document.createElement('a');
        a.href = dataStr;
        a.download = "headerdoctor_report.txt";
        a.click();
    }

    async exportPDF() {
        if (!this.lastScanData) return;
        if (typeof html2pdf === 'undefined') {
            this.showToast('PDF generator is still loading. Please try again.');
            return;
        }

        const exportBar = document.getElementById('export-bar');
        if (exportBar) exportBar.style.display = 'none';

        const element = document.getElementById('results-section');
        const opt = {
            margin: [15, 15, 15, 15],
            filename: 'headerdoctor_report.pdf',
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2, useCORS: true },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
        };

        try {
            this.showToast('Generating PDF...');
            await html2pdf().set(opt).from(element).save();
            this.showToast('PDF downloaded successfully!');
        } catch (err) {
            console.error('PDF export failed:', err);
            this.showToast('Failed to generate PDF.');
        } finally {
            if (exportBar) exportBar.style.display = 'flex';
        }
    }

    showToast(message) {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        container.appendChild(toast);
        // Trigger animation
        setTimeout(() => toast.classList.add('show'), 10);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return String(text).replace(/[&<>"']/g, m => map[m]);
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new HeaderDoctorApp();
});