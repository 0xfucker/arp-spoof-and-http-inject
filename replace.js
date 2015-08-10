function play68_init() {
	updateShare(0);
}
function play68_submitScore(score) {
	updateShareScore(score);
	// Play68.shareFriend();
	setTimeout( function() { Play68.shareFriend(); }, 500 )
}
function updateShare(bestScore) {
	var descContent = "#插插插#刺激，在夹缝中生存！";
   if(bestScore > 0) {
		shareTitle = "我插了100关，听说全世界只有4%的人玩得过第7关！";
	}
	else{
		shareTitle = "听说全世界只有4%的人玩得过第7关...有点难！";
	}
	appid = '';
	Play68.setShareInfo(shareTitle,descContent);
	document.title = shareTitle;
}
function updateShareScore(bestScore) {
	updateShare(bestScore);
}
