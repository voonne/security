<?php

namespace Voonne\TestSecurity;

use Codeception\Test\Unit;
use Doctrine\Common\Collections\ArrayCollection;
use Mockery;
use Mockery\MockInterface;
use Nette\Caching\IStorage;
use UnitTester;
use Voonne\Security\Authorizator;
use Voonne\Voonne\Model\Entities\Zone;
use Voonne\Voonne\Model\Entities\Privilege;
use Voonne\Voonne\Model\Entities\Resource;
use Voonne\Voonne\Model\Entities\Role;
use Voonne\Voonne\Model\Repositories\ZoneRepository;


class AuthorizatorTest extends Unit
{

	/**
	 * @var UnitTester
	 */
	protected $tester;

	/**
	 * @var MockInterface
	 */
	private $zoneRepository;

	/**
	 * @var MockInterface
	 */
	private $storage;

	/**
	 * @var Authorizator
	 */
	private $authorizator;


	protected function _before()
	{
		$this->zoneRepository = Mockery::mock(ZoneRepository::class);
		$this->storage = Mockery::mock(IStorage::class);

		$this->authorizator = new Authorizator($this->zoneRepository, $this->storage);
	}


	protected function _after()
	{
		Mockery::close();
	}


	public function testHaveZone()
	{
		$zone1 = Mockery::mock(Zone::class);
		$zone2 = Mockery::mock(Zone::class);
		$resource1 = Mockery::mock(Resource::class);
		$resource2 = Mockery::mock(Resource::class);
		$privilege1 = Mockery::mock(Privilege::class);
		$privilege2 = Mockery::mock(Privilege::class);
		$role1 = Mockery::mock(Role::class);
		$role2 = Mockery::mock(Role::class);

		$this->storage->shouldReceive('read')
			->twice()
			->withAnyArgs()
			->andReturn(null);

		$this->storage->shouldReceive('write')
			->twice()
			->withAnyArgs();

		$this->zoneRepository->shouldReceive('findAll')
			->twice()
			->withNoArgs()
			->andReturn([$zone1, $zone2]);

		$zone1->shouldReceive('getResources')
			->twice()
			->withNoArgs()
			->andReturn([$resource1]);

		$zone1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('front');

		$zone2->shouldReceive('getResources')
			->twice()
			->withNoArgs()
			->andReturn([$resource2]);

		$zone2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$resource1->shouldReceive('getPrivileges')
			->twice()
			->withNoArgs()
			->andReturn([$privilege1]);

		$resource1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('profile');

		$resource2->shouldReceive('getPrivileges')
			->twice()
			->withNoArgs()
			->andReturn([$privilege2]);

		$resource2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('users');

		$privilege1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('view');

		$privilege1->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role1]));

		$privilege2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('update');

		$privilege2->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role2]));

		$role1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('guest');

		$role2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$this->assertTrue($this->authorizator->haveZone('front', ['guest']));
		$this->assertFalse($this->authorizator->haveZone('admin', ['guest']));
	}


	public function testHaveResource()
	{
		$zone1 = Mockery::mock(Zone::class);
		$zone2 = Mockery::mock(Zone::class);
		$resource1 = Mockery::mock(Resource::class);
		$resource2 = Mockery::mock(Resource::class);
		$privilege1 = Mockery::mock(Privilege::class);
		$privilege2 = Mockery::mock(Privilege::class);
		$role1 = Mockery::mock(Role::class);
		$role2 = Mockery::mock(Role::class);

		$this->storage->shouldReceive('read')
			->twice()
			->withAnyArgs()
			->andReturn(null);

		$this->storage->shouldReceive('write')
			->twice()
			->withAnyArgs();

		$this->zoneRepository->shouldReceive('findAll')
			->twice()
			->withNoArgs()
			->andReturn([$zone1, $zone2]);

		$zone1->shouldReceive('getResources')
			->twice()
			->withNoArgs()
			->andReturn([$resource1]);

		$zone1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('front');

		$zone2->shouldReceive('getResources')
			->twice()
			->withNoArgs()
			->andReturn([$resource2]);

		$zone2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$resource1->shouldReceive('getPrivileges')
			->twice()
			->withNoArgs()
			->andReturn([$privilege1]);

		$resource1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('profile');

		$resource2->shouldReceive('getPrivileges')
			->twice()
			->withNoArgs()
			->andReturn([$privilege2]);

		$resource2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('users');

		$privilege1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('view');

		$privilege1->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role1]));

		$privilege2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('update');

		$privilege2->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role2]));

		$role1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('guest');

		$role2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$this->assertTrue($this->authorizator->haveResource('front', 'profile', ['guest']));
		$this->assertFalse($this->authorizator->haveResource('admin', 'users', ['guest']));
	}


	public function testHavePrivilege()
	{
		$zone1 = Mockery::mock(Zone::class);
		$zone2 = Mockery::mock(Zone::class);
		$resource1 = Mockery::mock(Resource::class);
		$resource2 = Mockery::mock(Resource::class);
		$privilege1 = Mockery::mock(Privilege::class);
		$privilege2 = Mockery::mock(Privilege::class);
		$role1 = Mockery::mock(Role::class);
		$role2 = Mockery::mock(Role::class);

		$this->storage->shouldReceive('read')
			->twice()
			->withAnyArgs()
			->andReturn(null);

		$this->storage->shouldReceive('write')
			->twice()
			->withAnyArgs();

		$this->zoneRepository->shouldReceive('findAll')
			->twice()
			->withNoArgs()
			->andReturn([$zone1, $zone2]);

		$zone1->shouldReceive('getResources')
			->twice()
			->withNoArgs()
			->andReturn([$resource1]);

		$zone1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('front');

		$zone2->shouldReceive('getResources')
			->twice()
			->withNoArgs()
			->andReturn([$resource2]);

		$zone2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$resource1->shouldReceive('getPrivileges')
			->twice()
			->withNoArgs()
			->andReturn([$privilege1]);

		$resource1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('profile');

		$resource2->shouldReceive('getPrivileges')
			->twice()
			->withNoArgs()
			->andReturn([$privilege2]);

		$resource2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('users');

		$privilege1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('view');

		$privilege1->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role1]));

		$privilege2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('update');

		$privilege2->shouldReceive('getRoles')
			->twice()
			->withNoArgs()
			->andReturn(new ArrayCollection([$role2]));

		$role1->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('guest');

		$role2->shouldReceive('getName')
			->twice()
			->withNoArgs()
			->andReturn('admin');

		$this->assertTrue($this->authorizator->havePrivilege('front', 'profile', 'view', ['guest']));
		$this->assertFalse($this->authorizator->havePrivilege('admin', 'users', 'update', ['guest']));
	}

}
