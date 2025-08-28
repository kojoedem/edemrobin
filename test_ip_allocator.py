import unittest
import ipaddress
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException

from database import Base
from models import User, IPBlock, Subnet, SubnetStatus
from ip_allocator import allocate_subnet

# Use an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class TestIPAllocator(unittest.TestCase):

    def setUp(self):
        """Set up a clean database for each test."""
        Base.metadata.create_all(bind=engine)
        self.db = TestingSessionLocal()

    def tearDown(self):
        """Clean up the database after each test."""
        self.db.close()
        Base.metadata.drop_all(bind=engine)

    def test_allocate_in_block_with_imported_subnet(self):
        """
        Test allocating a new subnet from a block that already contains
        a smaller, imported subnet.
        """
        # 1. Create a user
        user = User(username="testuser", password_hash="testpass", level=3, is_admin=True)
        self.db.add(user)
        self.db.commit()

        # 2. Create a parent IP block
        block = IPBlock(cidr="10.0.0.0/16", description="Test Block")
        self.db.add(block)
        self.db.commit()

        # 3. Create an existing imported subnet within the block
        imported_subnet = Subnet(
            cidr="10.0.10.0/24",
            status=SubnetStatus.imported,
            description="Imported from config",
            block_id=block.id
        )
        self.db.add(imported_subnet)
        self.db.commit()

        # 4. Try to allocate a new /24 subnet from the block
        new_subnet = allocate_subnet(
            db=self.db,
            block_id=block.id,
            user=user,
            subnet_size=24,
            description="New Allocation"
        )

        # 5. Assert that a new subnet was created
        self.assertIsNotNone(new_subnet)
        self.assertEqual(new_subnet.status, SubnetStatus.allocated)

        # 6. Assert that the new subnet is not the one that was already imported
        self.assertNotEqual(new_subnet.cidr, imported_subnet.cidr)

        # 7. Assert that the new subnet is the first available one
        self.assertEqual(new_subnet.cidr, "10.0.0.0/24")

if __name__ == '__main__':
    unittest.main()
