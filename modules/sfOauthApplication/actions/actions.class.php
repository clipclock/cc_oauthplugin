<?php

class sfOauthApplicationActions extends sfActions
{

	const ACTION_AUTH_RESPONSE = 'Response';

	protected function getClientId(sfWebRequest $request)
	{
		$client_id = $request->getParameter('client_id'); // OAuth 2.0
		if($client_id == NULL)
		{
			$client_id = $request->getParameter('oauth_consumer_key', ' ');
		} // OAuth 1.0

		return $client_id;
	}

	/**
	 *  Authorize an Application
	 * */
	public function executeAuthorize(sfWebRequest $request)
	{
		$user_id = $this->getUser()->getAttribute('user_id', null, 'sfGuardSecurityUser');
		$client_id = $this->getClientId($request);

		$oauth = new sfOAuth2PersistentServer();

		$this->consumer = $oauth->getConsumer($client_id); #; // Check if the client_id exist
		$this->forward404Unless($this->consumer);


		$this->redirect_uri = $request->getParameter('redirect_uri', $this->consumer['callback']);
		if($this->redirect_uri == NULL)
		{
			$this->redirect_uri = $this->consumer['callback'];
		}

		$oauth = new sfOAuth2PersistentServer();
		$oauth->setUserId($user_id);

		if (!$oauth->isApplicationAuthorized($client_id, $user_id, $this->consumer['scope']))
		{
			$oauth->authorizeApplication($this->consumer['consumer_key'], $user_id, $this->consumer['scope']);
		}

		if($oauth->isApplicationAuthorized($client_id, $user_id, $this->consumer['scope']))
		{
			$this->result = $oauth->finishClientAuthorization(1, array_merge($_GET, array('redirect_uri' => $this->redirect_uri, 'scope' => $this->consumer['scope'])));
			return self::ACTION_AUTH_RESPONSE;
		}
	}

	public function executeDeauthorize(sfWebRequest $request)
	{
		$oauth_token = $request->getParameter('oauth_token');

		if($oauth_token)
		{
			$oauth = new sfOAuth2PersistentServer();
			$oauth->deleteToken($oauth_token);
		}

		return sfView::NONE;
	}

	public function executeList(sfWebRequest $request)
	{
		$this->applications = sfOauthServerUserScopeQuery::create()->getApplicationsOf($this->getUser()->getAttribute('user_id', null, 'sfGuardSecurityUser'));
	}

	public function executeGetCode(sfWebRequest $request)
	{
		$this->setTemplate('authorize');
		$result['access_code'] = $request->getParameter('code');
		$this->result = $result;
		return self::ACTION_AUTH_RESPONSE;
	}

	public function executeDelete(sfWebRequest $request)
	{
		$this->forward404Unless($application = sfOauthServerUserScopeQuery::create()->find(array($request->getParameter('id'))), sprintf('Object does not exist (%s).', $request->getParameter('id')));

		if($application->getUserId() == $this->getUser()->getAttribute('user_id', null, 'sfGuardSecurityUser'))
		{
			$application->delete();
		}

		$this->redirect('application/list');
	}

}
