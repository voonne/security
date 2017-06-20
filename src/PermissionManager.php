<?php

/**
 * This file is part of the Voonne platform (http://www.voonne.org)
 *
 * Copyright (c) 2016 Jan Lavička (mail@janlavicka.name)
 *
 * For the full copyright and license information, please view the file licence.md that was distributed with this source code.
 */

namespace Voonne\Security;

use Doctrine\ORM\EntityManagerInterface;
use Nette\SmartObject;
use Voonne\Voonne\Model\Entities\Privilege;
use Voonne\Voonne\Model\Entities\Resource;
use Voonne\Voonne\Model\Entities\Zone;
use Voonne\Voonne\Model\Repositories\PrivilegeRepository;
use Voonne\Voonne\Model\Repositories\ResourceRepository;
use Voonne\Voonne\Model\Repositories\ZoneRepository;


class PermissionManager
{

	use SmartObject;

	/**
	 * @var EntityManagerInterface
	 */
	private $entityManager;

	/**
	 * @var ZoneRepository
	 */
	private $zoneRepository;

	/**
	 * @var ResourceRepository
	 */
	private $resourceRepository;

	/**
	 * @var PrivilegeRepository
	 */
	private $privilegeRepository;

	/**
	 * @var array
	 */
	private $zones = [];

	/**
	 * @var array
	 */
	private $resources = [];

	/**
	 * @var array
	 */
	private $privileges = [];


	public function __construct(
		EntityManagerInterface $entityManager,
		ZoneRepository $zoneRepository,
		ResourceRepository $resourceRepository,
		PrivilegeRepository $privilegeRepository
	) {
		$this->entityManager = $entityManager;
		$this->zoneRepository = $zoneRepository;
		$this->resourceRepository = $resourceRepository;
		$this->privilegeRepository = $privilegeRepository;
	}


	/**
	 * Adds domain into system.
	 *
	 * @param string $zone
	 * @param string|null $description
	 *
	 * @throws DuplicateEntryException
	 */
	public function addZone($zone, $description = null)
	{
		if (array_key_exists($zone, $this->zones)) {
			throw new DuplicateEntryException("Zone '$zone' has been already registered.");
		}

		$this->zones[$zone] = $description;
		$this->resources[$zone] = [];
	}


	/**
	 * Adds resource into zone.
	 *
	 * @param string $zone
	 * @param string $resource
	 * @param string|null $description
	 *
	 * @throws DuplicateEntryException
	 */
	public function addResource($zone, $resource, $description = null)
	{
		if (!array_key_exists($zone, $this->zones)) {
			throw new InvalidArgumentException("Zone '$zone' has not been registered.");
		}

		if (array_key_exists($resource, $this->resources[$zone])) {
			throw new DuplicateEntryException("Resource '$zone-$resource' has been already registered.");
		}

		$this->resources[$zone][$resource] = $description;
		$this->privileges[$zone][$resource] = [];
	}


	/**
	 * Adds privilege into resource.
	 *
	 * @param string $zone
	 * @param string $resource
	 * @param string $privilege
	 * @param string|null $description
	 *
	 * @throws DuplicateEntryException
	 */
	public function addPrivilege($zone, $resource, $privilege, $description = null)
	{
		if (!array_key_exists($zone, $this->zones)) {
			throw new InvalidArgumentException("Zone '$zone' has not been registered.");
		}

		if (!array_key_exists($resource, $this->resources[$zone])) {
			throw new InvalidArgumentException("Resource '$zone-$resource' has not been registered.");
		}

		if (array_key_exists($privilege, $this->privileges[$zone][$resource])) {
			throw new DuplicateEntryException("Privilege '$zone-$resource-$privilege' has been already registered.");
		}

		$this->privileges[$zone][$resource][$privilege] = $description;
	}


	/**
	 * Synchronize permissions between system and database.
	 */
	public function synchronize()
	{
		$zones = [];
		$resources = [];
		$privileges = [];

		foreach ($this->zoneRepository->findAll() as $zone) {
			/** @var Zone $zone */
			$zones[$zone->getName()] = $zone->getDescription();

			foreach ($zone->getResources() as $resource) {
				/** @var Resource $resource */
				$resources[$zone->getName()][$resource->getName()] = $resource->getDescription();

				foreach ($resource->getPrivileges() as $privilege) {
					/** @var Privilege $privilege */
					$privileges[$zone->getName()][$resource->getName()][$privilege->getName()] = $privilege->getDescription();
				}
			}
		}

		foreach ($this->zones as $zoneName => $zoneDescription) {
			if (!array_key_exists($zoneName, $zones)) {
				$zone = new Zone($zoneName, $zoneDescription);

				$this->entityManager->persist($zone);
			} else {
				$zone = $this->zoneRepository->findOneBy(['name' => $zoneName]);
			}

			foreach ($this->resources[$zoneName] as $resourceName => $resourceDescription) {
				if (!isset($resources[$zoneName]) || !array_key_exists($resourceName, $resources[$zoneName])) {
					$resource = new Resource($resourceName, $resourceDescription, $zone);

					$this->entityManager->persist($resource);
				} else {
					$resource = $this->resourceRepository->findOneBy(['name' => $resourceName]);
				}

				foreach ($this->privileges[$zoneName][$resourceName] as $privilegeName => $privilegeDescription) {
					if (!isset($privileges[$zoneName][$resourceName]) || !array_key_exists($privilegeName, $privileges[$zoneName][$resourceName])) {
						$privilege = new Privilege($privilegeName, $privilegeDescription, $resource);

						$this->entityManager->persist($privilege);
					}
				}
			}
		}

		$this->entityManager->flush();
	}

}
