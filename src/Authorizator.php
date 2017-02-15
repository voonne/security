<?php

/**
 * This file is part of the Voonne platform (http://www.voonne.org)
 *
 * Copyright (c) 2016 Jan Lavička (mail@janlavicka.name)
 *
 * For the full copyright and license information, please view the file licence.md that was distributed with this source code.
 */

namespace Voonne\Security;

use Nette\SmartObject;
use Voonne\Voonne\Model\Entities\Zone;
use Voonne\Voonne\Model\Entities\Privilege;
use Voonne\Voonne\Model\Entities\Role;
use Voonne\Voonne\Model\Repositories\ZoneRepository;


class Authorizator
{

	use SmartObject;

	/**
	 * @var ZoneRepository
	 */
	private $areaRepository;


	public function __construct(ZoneRepository $areaRepository)
	{
		$this->areaRepository = $areaRepository;
	}


	/**
	 * Has a user access to the area?
	 *
	 * @param string $area
	 *
	 * @return bool
	 */
	public function haveArea($area, array $roles)
	{
		$permissions = $this->getPermissions();

		if (isset($permissions[$area])) {
			foreach ($permissions[$area] as $resource) {
				foreach ($resource as $privilege) {
					if (!empty(array_intersect($privilege, $roles))) {
						return true;
					}
				}
			}
		}

		return false;
	}


	/**
	 * Has a user access to the resource?
	 *
	 * @param string $area
	 * @param string $resource
	 *
	 * @return bool
	 */
	public function haveResource($area, $resource, array $roles)
	{
		$permissions = $this->getPermissions();

		if (isset($permissions[$area][$resource])) {
			foreach ($permissions[$area][$resource] as $privilege) {
				if (!empty(array_intersect($privilege, $roles))) {
					return true;
				}
			}
		}

		return false;
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
	public function havePrivilege($area, $resource, $privilege, array $roles)
	{
		$permissions = $this->getPermissions();

		if (isset($permissions[$area][$resource][$privilege])) {
			return !empty(array_intersect($permissions[$area][$resource][$privilege], $roles));
		} else {
			return false;
		}
	}


	private function getPermissions()
	{
		$permissions = [];

		foreach ($this->areaRepository->findAll() as $area) {
			/** @var Zone $area */
			foreach ($area->getResources() as $resource) {
				/** @var Resource $resource */
				foreach ($resource->getPrivileges() as $privilege) {
					/** @var Privilege $privilege */
					$permissions[$area->getName()][$resource->getName()][$privilege->getName()] = array_map(function (Role $role) {
						return $role->getName();
					}, $privilege->getRoles()->toArray());
				}
			}
		}

		return $permissions;
	}

}
