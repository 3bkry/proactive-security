
import os from 'os';
import path from 'path';

export const SENTINEL_CONFIG_DIR = process.env.SENTINEL_CONFIG_DIR || path.join(os.homedir(), '.sentinel');
export const SENTINEL_LOG_DIR = process.env.SENTINEL_LOG_DIR || SENTINEL_CONFIG_DIR; // Default to same dir for now
export const SENTINEL_DATA_DIR = process.env.SENTINEL_DATA_DIR || SENTINEL_CONFIG_DIR;

export const CONFIG_FILE = path.join(SENTINEL_CONFIG_DIR, 'config.json');
export const BANNED_IPS_FILE = path.join(SENTINEL_DATA_DIR, 'banned_ips.json');
export const STATE_FILE = path.join(SENTINEL_DATA_DIR, 'state.json');
