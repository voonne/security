<?php

/**
 * This file is part of the Voonne platform (http://www.voonne.org)
 *
 * Copyright (c) 2016 Jan Lavička (mail@janlavicka.name)
 *
 * For the full copyright and license information, please view the file licence.md that was distributed with this source code.
 */

namespace Voonne\Security;

use Nette\Http\Session;
use Nette\SmartObject;
use Voonne\Model\IOException;
use Voonne\Voonne\Model\Entities\Domain;
use Voonne\Voonne\Model\Entities\Privilege;
use Voonne\Voonne\Model\Entities\Role;
use Voonne\Voonne\Model\Repositories\DomainRepository;
use Voonne\Voonne\Model\Repositories\UserRepository;


class User
{

	use SmartObject;

	/**
	 * @var \Nette\Security\User
	 */
	private $user;

	/**
	 * @var Session
	 */
	private $session;

	/**
	 * @var UserRepository
	 */
	private $userRepository;

	/**
	 * @var DomainRepository
	 */
	private $domainRepository;

	/**
	 * @var Authorizator
	 */
	private $authorizator;


	public function __construct(
		\Nette\Security\User $user,
		Session $session,
		UserRepository $userRepository,
		DomainRepository $domainRepository,
		Authorizator $authorizator
	)
	{
		$this->user = $user;
		$this->session = $session;
		$this->userRepository = $userRepository;
		$this->domainRepository = $domainRepository;
		$this->authorizator = $authorizator;
	}


	/**
	 * Returns entity of signed in user.
	 *
	 * @return \Voonne\Voonne\Model\Entities\User
	 *
	 * @throws InvalidStateException
	 * @throws IOException
	 */
	public function getUser()
	{
		if(!$this->user->isLoggedIn()) {
			throw new InvalidStateException('The user is not signed in.');
		}

		return $this->userRepository->find($this->user->getId());
	}


	/**
	 * Returns current domain for edit.
	 *
	 * @return Domain
	 */
	public function getCurrentDomain()
	{
		$section = $this->session->getSection('voonne.domain');

		if(isset($section['id'])) {
			try {
				return $this->domainRepository->find($section['id']);
			} catch (IOException $e) {}
		}

		$domains = $this->domainRepository->findAll();

		if(count($domains) == 0) {
			throw new InvalidStateException('There was no registered domain.');
		}

		$section['id'] = $domains[0]->getId();

		return $domains[0];
	}


	/**
	 * Sets current domain for edit.
	 *
	 * @param Domain $domain
	 */
	public function setCurrentDomain(Domain $domain)
	{
		$section = $this->session->getSection('voonne.domain');

		$section['id'] = $domain->getId();
	}


	/**
	 * Has a user access to the area?
	 *
	 * @param string $area
	 *
	 * @return bool
	 */
	public function haveArea($area)
	{
		return $this->authorizator->haveArea($area, $this->getRoles());
	}


	/**
	 * Has a user access to the resource?
	 *
	 * @param string $area
	 * @param string $resource
	 *
	 * @return bool
	 */
	public function haveResource($area, $resource)
	{
		return $this->authorizator->haveResource($area, $resource, $this->getRoles());
	}


	/**
	 * Has a user access to the privilege?
	 *
	 * @param string $area
	 * @param string $resource
	 * @param string $privilege
	 *
	 * @return bool
	 */
	public function havePrivilege($area, $resource, $privilege)
	{
		return $this->authorizator->havePrivilege($area, $resource, $privilege, $this->getRoles());
	}


	private function getRoles()
	{
		$roles = [];

		foreach ($this->getUser()->getRoles() as $role) {
			/** @var Role $role */
			$roles[] = $role->getName();
		}

		return $roles;
	}

}
