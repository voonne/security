<?php

/**
 * This file is part of the Voonne platform (http://www.voonne.org)
 *
 * Copyright (c) 2016 Jan Lavička (mail@janlavicka.name)
 *
 * For the full copyright and license information, please view the file licence.md that was distributed with this source code.
 */

namespace Voonne\Security;

use Nette\Caching\Cache;
use Nette\Caching\IStorage;
use Nette\SmartObject;
use Voonne\Voonne\Model\Entities\Resource;
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
	private $zoneRepository;

	/**
	 * @var Cache
	 */
	private $cache;

	const CACHE_NAMESPACE = 'Voonne.Security';


	public function __construct(ZoneRepository $zoneRepository, IStorage $storage)
	{
		$this->zoneRepository = $zoneRepository;
		$this->cache = new Cache($storage, self::CACHE_NAMESPACE);
	}


	/**
	 * Has a user access to the zone?
	 *
	 * @param string $zone
	 * @param array $roles
	 *
	 * @return bool
	 */
	public function haveZone($zone, array $roles)
	{
		$permissions = $this->getPermissions();

		if (isset($permissions[$zone])) {
			foreach ($permissions[$zone] as $resource) {
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
	 * @param string $zone
	 * @param string $resource
	 * @param array $roles
	 *
	 * @return bool
	 */
	public function haveResource($zone, $resource, array $roles)
	{
		$permissions = $this->getPermissions();

		if (isset($permissions[$zone][$resource])) {
			foreach ($permissions[$zone][$resource] as $privilege) {
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
	 * @param string $zone
	 * @param string $resource
	 * @param string $privilege
	 * @param array $roles
	 *
	 * @return bool
	 */
	public function havePrivilege($zone, $resource, $privilege, array $roles)
	{
		$permissions = $this->getPermissions();

		if (isset($permissions[$zone][$resource][$privilege])) {
			return !empty(array_intersect($permissions[$zone][$resource][$privilege], $roles));
		} else {
			return false;
		}
	}


	private function getPermissions()
	{
		$permissions = $this->cache->load('permissions');

		if (is_null($permissions)) {
			$permissions = [];

			foreach ($this->zoneRepository->findAll() as $zone) {
				/** @var Zone $zone */
				foreach ($zone->getResources() as $resource) {
					/** @var Resource $resource */
					foreach ($resource->getPrivileges() as $privilege) {
						/** @var Privilege $privilege */
						$permissions[$zone->getName()][$resource->getName()][$privilege->getName()] = array_map(function (Role $role) {
							return $role->getName();
						}, $privilege->getRoles()->toArray());
					}
				}
			}

			$this->cache->save('permissions', $permissions);
		}

		return $permissions;
	}

}
