/**
 * 网络接口（网卡）选择模块
 *
 * 负责：
 * 1. 用当前已保存的配置（interface / mac_address）先行回填界面，避免枚举
 *    尚未完成时下拉框为空；
 * 2. 调用 /api/interfaces 枚举本机所有可用抓包网卡，渲染为下拉列表，
 *    供多网卡场景下选择正确的网卡；
 * 3. 网卡切换时自动回填该网卡的硬件 MAC 地址（仍允许手动覆盖）；
 * 4. 将所选网卡 + MAC 地址通过 /api/config 保存并触发服务端重新监听。
 */
const Network = {
    devices: [],
    currentInterface: '',
    currentMac: '',
    loaded: false,

    /**
     * 用当前配置回填网卡/MAC 显示（在枚举完成前先展示已保存的值）
     * @param {Object} data - /api/config 返回的数据
     */
    applyCurrentConfig(data) {
        this.currentInterface = data.interface || '';
        this.currentMac = data.mac_address || '';
        document.getElementById('mac').value = this.currentMac;
        this.renderOptions();
    },

    /**
     * 拉取并渲染可选网卡列表
     */
    async loadDevices() {
        const authHeader = Session.getAuthHeader();
        const select = document.getElementById('networkInterface');
        const refreshButton = document.getElementById('refreshInterfacesButton');

        select.disabled = true;
        if (refreshButton) refreshButton.classList.add('spinning');

        try {
            const response = await API.getInterfaces(authHeader);

            if (response.status === 401) {
                Auth.logout();
                UI.showLoginMessage(I18n.t('error.authExpiredRelogin'));
                return;
            }

            if (!response.ok) {
                UI.showMessage(await Config.getErrorMessage(response, I18n.t('error.loadInterfacesFailed')), 'error');
                return;
            }

            this.devices = await response.json() || [];
            this.loaded = true;
        } catch (error) {
            UI.showMessage(I18n.t('error.loadInterfacesFailed'), 'error');
        } finally {
            select.disabled = false;
            if (refreshButton) refreshButton.classList.remove('spinning');
        }

        this.renderOptions();
    },

    /**
     * 生成网卡下拉选项的简短展示文案（避免文字过长被选择框截断）。
     * MAC 地址已在下方独立输入框完整展示，这里不再重复；仅显示最能
     * 帮助区分网卡的信息：名称/描述 + 首个 IPv4 地址 + 连接状态。
     * @param {Object} device - /api/interfaces 返回的单个网卡描述
     * @returns {string}
     */
    describeDevice(device) {
        const parts = [];
        parts.push(device.name || device.description || device.device);

        const ipv4 = (device.addresses || []).find((addr) => addr.indexOf(':') === -1);
        if (ipv4) parts.push(ipv4);

        parts.push(device.is_up ? I18n.t('main.interfaceUp') : I18n.t('main.interfaceDown'));
        return parts.join(' · ');
    },

    /**
     * 生成网卡的完整信息文案（名称、描述、MAC、全部地址、状态），
     * 用作 <option> 与 <select> 的 title 提示，鼠标悬停即可查看全部细节。
     * @param {Object} device - /api/interfaces 返回的单个网卡描述
     * @returns {string}
     */
    describeDeviceFull(device) {
        const parts = [];
        parts.push(device.name || device.description || device.device);
        if (device.name && device.description && device.description !== device.name) {
            parts.push(device.description);
        }
        if (device.mac_address) parts.push(`MAC: ${device.mac_address}`);
        if (device.addresses && device.addresses.length) parts.push(device.addresses.join(', '));
        parts.push(device.is_up ? I18n.t('main.interfaceUp') : I18n.t('main.interfaceDown'));
        return parts.join(' · ');
    },

    /**
     * 让下拉框收起状态下的 title 提示与当前选中项保持一致，
     * 这样即使选项文字被截断，鼠标悬停也能看到完整信息。
     */
    updateSelectTitle() {
        const select = document.getElementById('networkInterface');
        const selected = select.options[select.selectedIndex];
        select.title = selected ? (selected.title || selected.textContent) : '';
    },

    /**
     * 重新渲染下拉列表，尽量保留当前已选中的网卡
     */
    renderOptions() {
        const select = document.getElementById('networkInterface');
        const previousValue = select.value || this.currentInterface;
        select.innerHTML = '';

        if (!this.loaded) {
            const placeholder = document.createElement('option');
            placeholder.value = this.currentInterface;
            placeholder.textContent = this.currentInterface
                ? this.currentInterface
                : I18n.t('main.interfaceLoading');
            select.appendChild(placeholder);
            select.value = this.currentInterface;
            this.updateSelectTitle();
            return;
        }

        if (!this.devices.length) {
            const empty = document.createElement('option');
            empty.value = this.currentInterface;
            empty.textContent = I18n.t('main.interfaceNoneFound');
            select.appendChild(empty);
            select.value = this.currentInterface;
            this.updateSelectTitle();
            return;
        }

        let hasCurrent = false;
        this.devices.forEach((device) => {
            const option = document.createElement('option');
            option.value = device.device;
            option.textContent = this.describeDevice(device);
            option.title = this.describeDeviceFull(device);
            option.dataset.mac = device.mac_address || '';
            select.appendChild(option);
            if (device.device === this.currentInterface) hasCurrent = true;
        });

        // 若当前保存的网卡未出现在枚举结果中（例如设备已被拔出/禁用），
        // 仍将其作为一个选项保留，避免用户看不到自己已保存的配置。
        if (this.currentInterface && !hasCurrent) {
            const option = document.createElement('option');
            option.value = this.currentInterface;
            option.textContent = `${this.currentInterface} (${I18n.t('main.interfaceUnverified')})`;
            option.title = option.textContent;
            option.dataset.mac = this.currentMac;
            select.insertBefore(option, select.firstChild);
        }

        select.value = previousValue || this.currentInterface;
        this.updateSelectTitle();
    },

    /**
     * 网卡选择变化时，自动填充该网卡的硬件 MAC 地址，并同步提示文案
     */
    handleSelectionChange() {
        const select = document.getElementById('networkInterface');
        const selected = select.options[select.selectedIndex];
        if (selected && selected.dataset.mac) {
            document.getElementById('mac').value = selected.dataset.mac;
        }
        this.updateSelectTitle();
    },

    /**
     * 应用所选网卡与 MAC 地址设置
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async apply() {
        const authHeader = Session.getAuthHeader();
        const iface = document.getElementById('networkInterface').value.trim();
        const mac = document.getElementById('mac').value.trim();

        if (!iface) {
            return { success: false, message: I18n.t('error.interfaceRequired') };
        }
        if (!mac) {
            return { success: false, message: I18n.t('error.macRequired') };
        }

        try {
            const response = await API.saveConfig({ interface: iface, mac_address: mac }, authHeader);

            if (response.ok) {
                this.currentInterface = iface;
                this.currentMac = mac;
                return { success: true, message: I18n.t('success.networkSaved') };
            }

            if (response.status === 401) {
                Auth.logout();
                UI.showLoginMessage(I18n.t('error.authExpiredRelogin'));
                return { success: false, message: I18n.t('error.authExpired') };
            }

            return { success: false, message: await Config.getErrorMessage(response, I18n.t('error.networkApplyFailed')) };
        } catch (error) {
            return { success: false, message: I18n.t('error.networkSaveFailed') };
        }
    }
};
