// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

(() => {
    const darkThemes = ['ayu', 'navy', 'coal'];

    const isPrintPage = window.location.pathname.endsWith('/print.html');

    const isDark = () => !isPrintPage
        && darkThemes.some(theme => document.documentElement.classList.contains(theme));

    let wasDark = isDark();
    mermaid.initialize({ startOnLoad: true, theme: wasDark ? 'dark' : 'default' });

    // Simplest way to make mermaid re-render the diagrams in the new theme is via refreshing the page
    new MutationObserver(() => {
        if (isDark() !== wasDark) {
            window.location.reload();
        }
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
})();
