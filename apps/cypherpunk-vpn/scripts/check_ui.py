#!/usr/bin/env python3
"""Check responsive layout, keyboard recovery, themes, reduced motion and global routes."""
import argparse
import json
import time
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import Select, WebDriverWait

p = argparse.ArgumentParser()
p.add_argument('--url', default='http://localhost:5173')
p.add_argument('--geckodriver', default=str(Path.home() / '.local/bin/geckodriver'))
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=True)
options = webdriver.FirefoxOptions()
options.add_argument('-headless')
options.set_preference('ui.systemUsesDarkTheme', 0)
d = webdriver.Firefox(options=options, service=Service(a.geckodriver))
wait = WebDriverWait(d, 8)
checks = []

def check(name, truth):
    assert truth, name
    checks.append(name)

def title(text):
    wait.until(lambda browser: browser.find_element(By.TAG_NAME, 'h1').text == text)

def click(text):
    candidates = [b for b in d.find_elements(By.TAG_NAME, 'button') if text in b.text and b.is_displayed()]
    if not candidates:
        raise AssertionError('Missing visible button: ' + text)
    candidates[0].click()

def panel(opened):
    if bool(d.find_elements(By.CSS_SELECTOR, '.demo .body')) != opened:
        d.find_element(By.CSS_SELECTOR, '.demo .head').click()
    time.sleep(.1)

try:
    d.set_window_size(960, 766)
    d.get(a.url.rstrip('/') + '/?start=connected')
    title('Connected')
    time.sleep(1.4)
    check('GitHub cypherpunk logo is loaded locally', d.execute_script("const logo=document.querySelector('.wordmark img');return logo.complete && logo.naturalWidth === 1672 && new URL(logo.src).origin===location.origin"))
    d.save_screenshot(str(a.out / 'connected-light.png'))
    check('connected verdict and switch agree', d.find_element(By.CSS_SELECTOR, '[role=switch]').get_attribute('aria-checked') == 'true')
    check('connected indicator says verified', 'Verified' in d.find_element(By.CSS_SELECTOR, '.connection-badge').text)
    d.find_element(By.CSS_SELECTOR, '[aria-label="Switch to dark theme"]').click()
    check('manual dark theme applies to map and panel', d.execute_script("return document.documentElement.dataset.theme === 'dark' && getComputedStyle(document.querySelector('.land')).fill !== 'rgb(232, 231, 237)'"))
    check('cypherpunk logo remains visible in dark theme', d.execute_script("return getComputedStyle(document.querySelector('.wordmark img')).filter.includes('invert') && getComputedStyle(document.documentElement).filter === 'none'"))
    time.sleep(.9)
    d.save_screenshot(str(a.out / 'connected-dark.png'))
    d.find_element(By.CSS_SELECTOR, '[aria-label="Switch to light theme"]').click()
    d.find_element(By.ID, 'details-tab').click()
    check('details tab exposes controller values', 'ML-DSA-65' in d.find_element(By.ID, 'details-view').text)
    d.find_element(By.ID, 'connection-tab').click()
    d.find_element(By.CSS_SELECTOR, '[aria-label=Settings]').click()
    dialog = wait.until(lambda browser: browser.find_element(By.CSS_SELECTOR, '.sheet'))
    d.switch_to.active_element.send_keys(Keys.ESCAPE)
    wait.until(lambda browser: not browser.find_elements(By.CSS_SELECTOR, '.sheet'))
    check('settings closes with Escape and restores focus', d.switch_to.active_element.get_attribute('aria-label') == 'Settings')
    d.find_element(By.CSS_SELECTOR, '[role=switch]').click()
    title('Disconnected')
    d.find_element(By.CSS_SELECTOR, '[role=switch]').click()
    wait.until(lambda browser: browser.find_elements(By.CSS_SELECTOR, 'input[type=password]'))
    d.switch_to.active_element.send_keys(Keys.ESCAPE)
    title('Disconnected')
    check('PIN cancellation returns to blocked state', not d.find_elements(By.CSS_SELECTOR, '.dialog') and 'blocked' in d.find_element(By.CSS_SELECTOR, '.line').text)
    panel(True)
    click('Service stops')
    title('Status unknown')
    panel(False)
    check('unknown status never displays a verified badge', 'Verified' not in d.find_element(By.CSS_SELECTOR, '.connection-badge').text)
    check('unknown status disables connection switch', not d.find_element(By.CSS_SELECTOR, '[role=switch]').is_enabled())
    click('Start the service')
    title('Disconnected')
    for width, height in [(800, 686), (360, 726)]:
        d.set_window_size(width, height)
        time.sleep(.4)
        actual_width = d.execute_script('return innerWidth')
        check(f'no page overflow at actual viewport {actual_width}px (requested {width})', d.execute_script('return document.documentElement.scrollWidth <= innerWidth && document.documentElement.scrollHeight <= innerHeight'))
        check(f'connect control visible at actual viewport {actual_width}px', d.find_element(By.CSS_SELECTOR, '[role=switch]').is_displayed())
        d.save_screenshot(str(a.out / f'disconnected-{width}px.png'))
    d.set_window_size(960, 766)
    d.get(a.url.rstrip('/') + '/?start=connected')
    title('Connected')
    routes = [('single-singapore', ['sin']), ('four-hop-pacific', ['syd', 'tyo', 'lax', 'tor']), ('three-hop-africa', ['lon', 'bom', 'jnb'])]
    for name, ids in routes:
        panel(True)
        for b in d.find_elements(By.CSS_SELECTOR, '.demo .hops button'):
            if b.text.startswith(str(len(ids)) + ' '):
                b.click()
                break
        for i, site in enumerate(ids):
            Select(d.find_elements(By.CSS_SELECTOR, '.demo .hop select')[i]).select_by_value(site)
        panel(False)
        title('Connected')
        time.sleep(.3)
        check(name + ' keeps every hop', len(d.find_elements(By.CSS_SELECTOR, '.server')) == len(ids))
        check(name + ' has no clipped pin labels', d.execute_script("const box=document.querySelector('.map').getBoundingClientRect();return [...document.querySelectorAll('.label-bg')].every(e=>{let r=e.getBoundingClientRect();return r.left>=box.left&&r.right<=box.right&&r.top>=box.top&&r.bottom<=box.bottom})"))
        d.save_screenshot(str(a.out / f'{name}.png'))
    check('assets stay on the local origin', d.execute_script("return performance.getEntriesByType('resource').every(r=>new URL(r.name).origin===location.origin || r.name.startsWith('data:'))"))
finally:
    d.quit()

options.set_preference('ui.prefersReducedMotion', 1)
d = webdriver.Firefox(options=options, service=Service(a.geckodriver))
wait = WebDriverWait(d, 8)
try:
    d.set_window_size(960, 766)
    d.get(a.url.rstrip('/') + '/?start=connected')
    title('Connected')
    check('reduced-motion preference disables decorative animation', d.execute_script("return matchMedia('(prefers-reduced-motion: reduce)').matches && parseFloat(getComputedStyle(document.querySelector('.route.live')).animationDuration) < .001"))
finally:
    d.quit()
(a.out / 'ui-checks.json').write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))
print(json.dumps({'passed': len(checks), 'checks': checks}, indent=2))
