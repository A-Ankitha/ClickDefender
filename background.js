chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    console.log("User visited:", tab.url);
    // Later: Check against blacklist/whitelist here
  }
});
