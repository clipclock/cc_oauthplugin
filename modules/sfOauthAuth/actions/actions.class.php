<?php

class sfOauthAuthActions extends sfActions
{

	public function preExecute()
	{
		$sfoauth = new sfOauthServerBase(sfContext::getInstance(), $this->getModuleName(), $this->getActionName());
		$sfoauth->connectEvent();
		sfConfig::set('sf_web_debug', false);
	}

	/*
	 *Recup RequestToken OAuth 1.0
	 */
	public function executeRequestToken(sfWebRequest $request)
	{
		$oauthServer = new sfOauthServer(new sfOAuthDataStore());
		$req = OAuthRequest::from_request(NULL, $request->getUri());
		$this->token = $oauthServer->fetch_request_token($req);

		return $this->setTemplate('token');

	}

	/*
	  *Get AccessToken OAuth 1.0 and OAuth 2.0
	  */
	public function executeAccessToken(sfWebRequest $request)
	{

		$req = OAuthRequest::from_request(NULL, $request->getUri()); // To get variable in header

		if($req->get_parameter('oauth_version') == '1.0')
		{
			$oauthServer = new sfoauthserver(new sfOAuthDataStore());
			$req = OAuthRequest::from_request(NULL, $request->getUri());

			$q = sfOauthServerRequestTokenQuery::create()->findOneByToken($request->getParameter('oauth_token'));
			$this->token = $oauthServer->fetch_access_token($req);

			if($q->getUserId() == NULL && $q->getScope())
			{
				throw new OAuthException('Token unauthorized');
			}

			return $this->setTemplate('token');

		}
		else
		{
			$oauthServer2 = new sfOAuth2PersistentServer();
			$q = $oauthServer2->getAuthCodePublic($request->getParameter('code'));
			#$q = sfOauthServerRequestTokenQuery::create()->findOneByToken($request->getParameter('code'));
			$oauthServer2->setUserId($q['user_id']);
			$oauthServer2->grantAccessToken($q['scope']);
			return sfView::NONE;
		}
	}


}
