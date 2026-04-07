
/**
 * Forbidden headers can't be set using Fetch API :(
 * we use DeclarativeNetRequest API to set these headers
 */

import Fetcher from './fetcher.js';
import ExtApi  from './ext-api.js';
import Storage from './storage.js';
import fnv1a   from '../../vendor/fnv1a/index.js';


async function get(url, requestOptions = {}) {
  return await modifyHeadersWhenFetch('get', url, requestOptions);
}

async function head(url, requestOptions = {}) {
  return await modifyHeadersWhenFetch('head', url, requestOptions);
}


async function modifyHeadersWhenFetch(method, url, requestOptions) {
  const {newHeaders, dnrRule} = await handleHeaders(url, requestOptions.headers);
  const newOptions = Object.assign({},
    requestOptions, {headers: newHeaders});
  if (!dnrRule) {
    return await Fetcher[method](url, newOptions);
  }


  let updatedDnrRule = false;
  try {
    const options = {removeRuleIds: [dnrRule.id], addRules: [dnrRule]};
    await ExtApi.updateDnrSessionRules(options);
    updatedDnrRule = true;
    // console.debug("set DNR session rule: ", dnrRule.id, url);
  } catch(e) {
    console.error("failed to update DNR session rules [before request]", e);
    // it's OK, we just can't modify these forbidden headers, in this case
  }

  let result, error;
  try {
    result = await Fetcher[method](url, newOptions)
  } catch(e) { error = e }

  if (updatedDnrRule) {
    try {
      const options = {removeRuleIds: [dnrRule.id]};
      await ExtApi.updateDnrSessionRules(options);
      // console.debug("remove DNR session rule: ", dnrRule.id, url);
    } catch(e) {
      console.error("failed to update DNR session rules [after request]", e);
      // It's OK, the next time we request the same url,
      // we'll remove it when add rule.
      // or it'll be removed when session ends.
    }
  }

  try {
    await Storage.session.remove(ruleId2Key(dnrRule.id));
  } catch(e) {
    console.error("failed to remove DNR rule id from storage", dnrRule.id, url);
    console.error(e);
    // It's OK, it'll be removed when session ends.
  }

  if (error) { throw error; }
  return result;
}


// forbidden headers that we want to modify
const FORBIDDEN_HEADERS = ['Referer', 'Origin', 'Cookie'];

async function handleHeaders(url, headers = {}) {
  const newHeaders = {};
  const requestHeaders = [];

  for (const name in headers) {
    const value = headers[name];

    if (FORBIDDEN_HEADERS.indexOf(name) == -1) {
      // normal headers, can be passed to fetch
      newHeaders[name] = value;
      continue;
    }

    const modifyInfo = {header: name};
    if (value == '$REMOVE_ME') { // see requestParams.js
      modifyInfo.operation = 'remove';
    } else if (name == 'Cookie') {
      if (value == '$SAME_ORIGIN') { // fetch cookie
        const cookie = await ExtApi.getUrlCookieStr(url);
        if (cookie == '') {
          modifyInfo.operation = 'remove';
        } else {
          modifyInfo.operation = 'set';
          modifyInfo.value = cookie;
        }
      } else {
        modifyInfo.operation = 'set';
        modifyInfo.value = value;
      }
    } else {
      modifyInfo.operation = 'set';
      modifyInfo.value = value;
    }
    requestHeaders.push(modifyInfo);
  }

  let dnrRule = undefined;
  if (requestHeaders.length > 0) {
    try {
      const ruleId = await urlToRuleId(url);
      dnrRule = {
        id: ruleId,
        priority: 10,
        condition: { urlFilter: url },
        action: {
          type: 'modifyHeaders',
          requestHeaders,
        }
      };
    } catch(e) {
      console.error("Unexpected error occurred when get Rule id");
      console.error("URL: ", url);
      console.error(e);
    }
  }

  return {newHeaders, dnrRule};
}


// There's a disgusting bug on Chromium that complain
// "expected rule id to be an integer, but got number"
// It turns out that Chromium use a signed 32bit integer as rule id,
// Which is just not the same as the documentation shows (A javascript number)
const DNR_RULE_ID_MAX = 2147483646; // 2^^31 - 1
function toValidRuleId(id) {
  const v = id % DNR_RULE_ID_MAX;
  return (v == 0 ? 1 : v); // Rule ID can not be zero
}

async function urlToRuleId(url) {
  const hash = Number(fnv1a(url, {size: 32}));
  let newId = toValidRuleId(hash);
  return await getUniqueRuleId(newId, url);
}

function ruleId2Key(id) { return `DNR_SESSION_RULE_ID_${id}`; }

async function getUniqueRuleId(newId, url) {
  const key = ruleId2Key(newId);
  const storedUrl = await Storage.session.get(key);
  if (storedUrl) {
    if (storedUrl == url) {
      return newId;
    } else {
      // newId collide with other ID.
      // just try the next one
      return await getUniqueRuleId(toValidRuleId(newId + 1), url);
    }
  } else {
    // store newId
    await Storage.session.set(key, url);
    return newId;
  }
}


export default {get, head};
