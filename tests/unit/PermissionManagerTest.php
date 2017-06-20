<?php

namespace Voonne\TestSecurity;

use Codeception\Test\Unit;
use Doctrine\ORM\EntityManagerInterface;
use Mockery;
use Mockery\MockInterface;
use UnitTester;
use Voonne\Security\DuplicateEntryException;
use Voonne\Security\InvalidArgumentException;
use Voonne\Security\PermissionManager;
use Voonne\Voonne\Model\Entities\Privilege;
use Voonne\Voonne\Model\Entities\Resource;
use Voonne\Voonne\Model\Entities\Zone;
use Voonne\Voonne\Model\Repositories\PrivilegeRepository;
use Voonne\Voonne\Model\Repositories\ResourceRepository;
use Voonne\Voonne\Model\Repositories\ZoneRepository;


class PermissionManagerTest extends Unit
{

	/**
	 * @var UnitTester
	 */
	protected $tester;

	/**
	 * @var MockInterface
	 */
	private $entityManager;

	/**
	 * @var MockInterface
	 */
	private $zoneRepository;

	/**
	 * @var MockInterface
	 */
	private $resourceRepository;

	/**
	 * @var MockInterface
	 */
	private $privilegeRepository;

	/**
	 * @var PermissionManager
	 */
	private $permissionManager;


	protected function _before()
	{
		$this->entityManager = Mockery::mock(EntityManagerInterface::class);
		$this->zoneRepository = Mockery::mock(ZoneRepository::class);
		$this->resourceRepository = Mockery::mock(ResourceRepository::class);
		$this->privilegeRepository = Mockery::mock(PrivilegeRepository::class);

		$this->permissionManager = new PermissionManager(
			$this->entityManager,
			$this->zoneRepository,
			$this->resourceRepository,
			$this->privilegeRepository
		);
	}


	protected function _after()
	{
		Mockery::mock();
	}


	public function testAddZone()
	{
		$this->permissionManager->addZone('admin');
		$this->permissionManager->addZone('front');
	}


	public function testAddZoneDuplicateEntry()
	{
		$this->permissionManager->addZone('admin');

		$this->expectException(DuplicateEntryException::class);

		$this->permissionManager->addZone('admin');
	}


	public function testAddResource()
	{
		$this->permissionManager->addZone('admin');
		$this->permissionManager->addResource('admin', 'users');
		$this->permissionManager->addResource('admin', 'roles');
	}


	public function testAddResourceDuplicateEntry()
	{
		$this->permissionManager->addZone('admin');
		$this->permissionManager->addResource('admin', 'users');

		$this->expectException(DuplicateEntryException::class);

		$this->permissionManager->addResource('admin', 'users');
	}


	public function testAddResourceZoneNotExist()
	{
		$this->expectException(InvalidArgumentException::class);

		$this->permissionManager->addResource('admin','users');
	}


	public function testAddPrivilege()
	{
		$this->permissionManager->addZone('admin');
		$this->permissionManager->addResource('admin', 'users');
		$this->permissionManager->addPrivilege('admin', 'users', 'create');
		$this->permissionManager->addPrivilege('admin', 'users', 'view');
	}


	public function testAddPrivilegeDuplicateEntry()
	{
		$this->permissionManager->addZone('admin');
		$this->permissionManager->addResource('admin', 'users');
		$this->permissionManager->addPrivilege('admin', 'users', 'create');

		$this->expectException(DuplicateEntryException::class);

		$this->permissionManager->addPrivilege('admin', 'users', 'create');
	}


	public function testAddPrivilegeZoneNotExist()
	{
		$this->expectException(InvalidArgumentException::class);

		$this->permissionManager->addPrivilege('admin','users', 'create');
	}


	public function testAddPrivilegeResourceNotExist()
	{
		$this->permissionManager->addZone('admin');

		$this->expectException(InvalidArgumentException::class);

		$this->permissionManager->addPrivilege('admin','users', 'create');
	}



	public function testSynchronize()
	{
		$this->permissionManager->addZone('admin');
		$this->permissionManager->addResource('admin', 'users');
		$this->permissionManager->addPrivilege('admin', 'users', 'create');

		$this->zoneRepository->shouldReceive('findAll')
			->once()
			->withNoArgs()
			->andReturn([]);

		$this->entityManager->shouldReceive('persist')
			->once()
			->with(Mockery::type(Zone::class));

		$this->entityManager->shouldReceive('persist')
			->once()
			->with(Mockery::type(Resource::class));

		$this->entityManager->shouldReceive('persist')
			->once()
			->with(Mockery::type(Privilege::class));

		$this->entityManager->shouldReceive('flush')
			->once()
			->withNoArgs();

		$this->permissionManager->synchronize();
	}


	public function testNothingToSynchronize()
	{
		$zone = Mockery::mock(Zone::class);
		$resource = Mockery::mock(Resource::class);
		$privilege = Mockery::mock(Privilege::class);

		$this->permissionManager->addZone('admin');
		$this->permissionManager->addResource('admin', 'users');
		$this->permissionManager->addPrivilege('admin', 'users', 'create');

		$zone->shouldReceive('getName')
			->times(3)
			->withNoArgs()
			->andReturn('admin');

		$zone->shouldReceive('getDescription')
			->once()
			->withNoArgs()
			->andReturn(null);

		$zone->shouldReceive('getResources')
			->once()
			->withNoArgs()
			->andReturn([$resource]);

		$resource->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('users');

		$resource->shouldReceive('getDescription')
			->once()
			->withNoArgs()
			->andReturn(null);

		$resource->shouldReceive('getPrivileges')
			->once()
			->withNoArgs()
			->andReturn([$privilege]);

		$privilege->shouldReceive('getName')
			->once()
			->withNoArgs()
			->andReturn('create');

		$privilege->shouldReceive('getDescription')
			->once()
			->withNoArgs()
			->andReturn(null);

		$this->zoneRepository->shouldReceive('findAll')
			->once()
			->withNoArgs()
			->andReturn([$zone]);

		$this->zoneRepository->shouldReceive('findOneBy')
			->once()
			->with(['name' => 'admin'])
			->andReturn($zone);

		$this->resourceRepository->shouldReceive('findOneBy')
			->once()
			->with(['name' => 'users'])
			->andReturn($resource);

		$this->entityManager->shouldReceive('flush')
			->once()
			->withNoArgs();

		$this->permissionManager->synchronize();
	}

}
